"""Conformance and detectability checks over one sender's datagrams."""

import struct
from collections import Counter

from .spec import (BASE, COOKIE, INIT, RESP, TRANSPORT, Classified, Config,
                   classify, match_tags)

BURST_GAP = 0.05  # pre-handshake packets go out in one batch with the initiation


def finding(fid, sev, msg, **kw):
    d = {"id": fid, "severity": sev, "message": msg}
    d.update(kw)
    return d


def check_stream(cfg: Config, dgrams, role: str) -> dict:
    """dgrams: Datagram list sent by one peer, in capture order."""
    cls = [classify(cfg, d.payload) for d in dgrams]
    out = []

    # --- pre-handshake packets (I1-I5 then Jc junk) sent back-to-back before each initiation
    if role == "initiator":
        expected_i = len(cfg.ipackets)
        want = expected_i + cfg.jc
        n_init = 0
        for idx, c in enumerate(cls):
            if c.kind != INIT:
                continue
            n_init += 1
            # burst: datagrams immediately preceding the initiation, each within BURST_GAP of the next
            j = idx
            while j > 0 and dgrams[j].ts - dgrams[j - 1].ts <= BURST_GAP and cls[j - 1].kind not in (INIT, RESP):
                j -= 1
            pre = dgrams[j:idx]
            if len(pre) > want:  # data packets that happened to be sent right before a rekey
                pre = pre[-want:] if want else []
            if len(pre) != want:
                out.append(finding("SPEC-PRE-COUNT", "error",
                                   f"initiation #{n_init}: {len(pre)} pre-handshake datagrams, spec expects "
                                   f"{expected_i} I-packets + Jc={cfg.jc} junk = {want}"))
            ipk, junk = pre[:expected_i], pre[expected_i:]
            for k, (tags, d2) in enumerate(zip(cfg.ipackets, ipk), start=1):
                why = match_tags(tags, d2.payload, now=d2.ts)
                if why:
                    out.append(finding("SPEC-I", "error", f"initiation #{n_init}: I{k} does not match its tags: {why}"))
            for jd in junk:
                n = len(jd.payload)
                if not (cfg.jmin <= n <= cfg.jmax):
                    out.append(finding("SPEC-JUNK-SIZE", "error",
                                       f"initiation #{n_init}: junk datagram of {n} bytes outside [Jmin={cfg.jmin}, Jmax={cfg.jmax}]"))
            for k in range(j, idx):
                cls[k] = Classified("pre-handshake")
        if n_init == 0:
            out.append(finding("NO-INIT", "error", "no handshake initiation recognised in capture"))

    # --- transport packets sent with the wrong S4 padding
    s4 = cfg.pad[TRANSPORT]
    lo, hi = cfg.hdr[TRANSPORT]
    for k, (d, c) in enumerate(zip(dgrams, cls)):
        if c.kind != "other" or cfg.hp_key:
            continue
        p = d.payload
        for pad in range(0, min(len(p) - 31, 256)):
            if pad == s4:
                continue
            h = struct.unpack("<I", p[pad:pad + 4])[0]
            if lo <= h <= hi and len(p) >= pad + 32:
                ctr = struct.unpack("<Q", p[pad + 8:pad + 16])[0]
                if ctr < 1 << 20:  # plausible counter, not random bytes
                    out.append(finding("SPEC-S4-WRONG", "error",
                                       f"datagram {k} ({len(p)} B) is a transport message with {pad} bytes of padding, "
                                       f"config S4={s4} (counter {ctr}); the peer cannot parse it", index=k, pad=pad))
                    cls[k] = Classified("transport-wrong-pad")
                    break
    counts = Counter(c.kind for c in cls)

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
    sz = Counter(len(d.payload) for d, c in zip(dgrams, cls) if c.kind in (INIT, RESP, COOKIE))
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
