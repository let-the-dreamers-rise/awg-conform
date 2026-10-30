"""AmneziaWG wire format, written from the published parameter reference
(amneziawg-go README, "Configuration" section) rather than from any one
implementation's code.

Message sizes are the WireGuard ones: initiation 148, response 92,
cookie reply 64, transport header 16 + AEAD tag 16.
"""

import re
import struct
from dataclasses import dataclass, field

INIT, RESP, COOKIE, TRANSPORT = "init", "response", "cookie", "transport"
BASE = {INIT: 148, RESP: 92, COOKIE: 64, TRANSPORT: 32}
PAD = {INIT: "s1", RESP: "s2", COOKIE: "s3", TRANSPORT: "s4"}
HDR = {INIT: "h1", RESP: "h2", COOKIE: "h3", TRANSPORT: "h4"}
WG_TYPE = {INIT: 1, RESP: 2, COOKIE: 3, TRANSPORT: 4}
HP_NONCE = 12


def parse_range(v) -> tuple[int, int]:
    s = str(v).strip()
    if "-" in s:
        lo, hi = s.split("-", 1)
        return int(lo), int(hi)
    return int(s), int(s)


@dataclass
class Config:
    raw: dict
    jc: int = 0
    jmin: int = 0
    jmax: int = 0
    pad: dict = field(default_factory=dict)
    hdr: dict = field(default_factory=dict)
    ipackets: list = field(default_factory=list)
    hp_key: bytes | None = None
    random_trailers: bool = False
    content_padding: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        c = cls(raw=dict(d))
        c.jc = int(d.get("jc", 0))
        c.jmin = int(d.get("jmin", 0))
        c.jmax = int(d.get("jmax", 0))
        for t in (INIT, RESP, COOKIE, TRANSPORT):
            c.pad[t] = int(d.get(PAD[t], 0))
            c.hdr[t] = parse_range(d[HDR[t]]) if HDR[t] in d else (WG_TYPE[t], WG_TYPE[t])
        for i in range(1, 6):
            spec = d.get(f"i{i}")
            if spec:
                c.ipackets.append(parse_tags(spec))
        if d.get("header_protection_key"):
            c.hp_key = bytes.fromhex(d["header_protection_key"])
        c.random_trailers = str(d.get("random_trailers", "")).lower() in ("1", "true")
        c.content_padding = bool(d.get("content_padding_addition"))
        return c


# ---- CPS (I1-I5) tag grammar -------------------------------------------------

TAG_RE = re.compile(r"<([a-z]+)(?:\s+([^>]*))?>")


def parse_tags(spec: str) -> list[tuple[str, object]]:
    """Return [(kind, arg)] where kind in b, r, rc, rd, t, c."""
    out = []
    for m in TAG_RE.finditer(spec):
        kind, arg = m.group(1), (m.group(2) or "").strip()
        if kind == "b":
            h = arg[2:] if arg.startswith("0x") else arg
            out.append(("b", bytes.fromhex(h)))
        elif kind in ("r", "rc", "rd"):
            out.append((kind, int(arg)))
        elif kind in ("t", "c"):
            out.append((kind, 4))
        else:
            out.append((kind, arg))
    return out


def tag_len(tags) -> int:
    n = 0
    for kind, arg in tags:
        n += len(arg) if kind == "b" else (arg if isinstance(arg, int) else 0)
    return n


def match_tags(tags, payload: bytes, now: float | None = None) -> str | None:
    """None if the payload matches the template, else a reason."""
    if len(payload) != tag_len(tags):
        return f"length {len(payload)} != template {tag_len(tags)}"
    off = 0
    for kind, arg in tags:
        if kind == "b":
            if payload[off:off + len(arg)] != arg:
                return f"<b> bytes differ at offset {off}"
            off += len(arg)
        elif kind == "rc":
            seg = payload[off:off + arg]
            if not all(65 <= x <= 90 or 97 <= x <= 122 for x in seg):
                return f"<rc> non-letter at offset {off}"
            off += arg
        elif kind == "rd":
            seg = payload[off:off + arg]
            if not all(48 <= x <= 57 for x in seg):
                return f"<rd> non-digit at offset {off}"
            off += arg
        elif kind == "t":
            ts = struct.unpack(">I", payload[off:off + 4])[0]
            if now is not None and abs(ts - now) > 120:
                return f"<t> timestamp {ts} is {ts - now:+.0f}s from capture time"
            off += 4
        else:
            off += arg if isinstance(arg, int) else 0
    return None


# ---- header protection ---------------------------------------------------------

def hp_keystream(key: bytes, nonce12: bytes, n: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    enc = Cipher(algorithms.ChaCha20(key, b"\x00\x00\x00\x00" + nonce12), mode=None).encryptor()
    return enc.update(b"\x00" * n)


# ---- classifier ----------------------------------------------------------------

@dataclass
class Classified:
    kind: str           # init/response/cookie/transport/other
    header: int | None = None
    pad: int = 0
    body: bytes = b""   # message after padding, header-unprotected


def classify(cfg: Config, p: bytes) -> Classified:
    ks = None
    if cfg.hp_key and len(p) >= HP_NONCE:
        ks = hp_keystream(cfg.hp_key, p[:HP_NONCE], 148)
    for kind in (INIT, RESP, COOKIE, TRANSPORT):
        pad = cfg.pad[kind]
        need = pad + BASE[kind]
        if kind == TRANSPORT:
            ok = len(p) >= need
        else:
            ok = len(p) == need or (cfg.random_trailers and len(p) > need)
        if not ok:
            continue
        hb = bytearray(p[pad:pad + 4])
        if ks is not None:
            hb = bytearray(a ^ b for a, b in zip(hb, ks[:4]))
        h = struct.unpack("<I", bytes(hb))[0]
        lo, hi = cfg.hdr[kind]
        if lo <= h <= hi:
            body = p[pad:] if kind == TRANSPORT else p[pad:pad + BASE[kind]]
            if ks is not None:
                span = 16 if kind == TRANSPORT else BASE[kind]
                body = bytes(a ^ b for a, b in zip(body[:span], ks[:span])) + body[span:]
            return Classified(kind, h, pad, body)
    return Classified("other")
