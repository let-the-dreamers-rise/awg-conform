"""Minimal pcap reader for UDP/IPv4 captures (no third-party deps)."""

import struct
from dataclasses import dataclass


@dataclass
class Datagram:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    payload: bytes


def _ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def read_udp(path: str) -> list[Datagram]:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return []
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
    else:
        raise ValueError("not a pcap file")
    nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    out = []
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        ts = sec + frac / (1e9 if nano else 1e6)
        if linktype == 1:  # Ethernet
            if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
                continue
            ip = pkt[14:]
        elif linktype == 113:  # Linux cooked v1
            if len(pkt) < 16 or pkt[14:16] != b"\x08\x00":
                continue
            ip = pkt[16:]
        elif linktype == 276:  # Linux cooked v2
            if len(pkt) < 20 or pkt[0:2] != b"\x08\x00":
                continue
            ip = pkt[20:]
        elif linktype in (101, 228):  # raw IPv4
            ip = pkt
        else:
            continue
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        udp = ip[ihl:total]
        if len(udp) < 8:
            continue
        sport, dport, ulen = struct.unpack(">HHH", udp[:6])
        out.append(Datagram(ts, _ip(ip[12:16]), sport, _ip(ip[16:20]), dport, bytes(udp[8:ulen])))
    return out
