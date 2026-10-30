import os
import struct
import time
import unittest

from awgconform.checks import check_stream
from awgconform.pcap import Datagram
from awgconform.spec import Config, classify, hp_keystream, match_tags, parse_tags

CFG = {"jc": 2, "jmin": 10, "jmax": 20, "s1": 15, "s2": 20, "s3": 5, "s4": 13,
       "h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800",
       "i1": "<b 0xc0ffee><r 4><t><rc 3><rd 2>"}


def msg(h, size):
    return struct.pack("<I", h) + os.urandom(size - 4)


def dg(p):
    return Datagram(time.time(), "10.0.0.1", 1, "10.0.0.2", 2, p)


class Spec(unittest.TestCase):
    def test_classify_each_type(self):
        c = Config.from_dict(CFG)
        self.assertEqual(classify(c, os.urandom(15) + msg(150, 148)).kind, "init")
        self.assertEqual(classify(c, os.urandom(20) + msg(350, 92)).kind, "response")
        self.assertEqual(classify(c, os.urandom(5) + msg(550, 64)).kind, "cookie")
        self.assertEqual(classify(c, os.urandom(13) + msg(750, 32 + 48)).kind, "transport")
        self.assertEqual(classify(c, os.urandom(15) + msg(250, 148)).kind, "other")

    def test_tags(self):
        tags = parse_tags(CFG["i1"])
        good = bytes.fromhex("c0ffee") + os.urandom(4) + struct.pack(">I", int(time.time())) + b"aZq" + b"42"
        self.assertIsNone(match_tags(tags, good, now=time.time()))
        self.assertIn("<b>", match_tags(tags, b"\0" + good[1:], now=time.time()))
        self.assertIn("<rd>", match_tags(tags, good[:-1] + b"x", now=time.time()))
        self.assertIn("length", match_tags(tags, good + b"!", now=time.time()))

    def test_header_protection_roundtrip(self):
        key = bytes(range(32))
        d = dict(CFG, header_protection_key=key.hex())
        c = Config.from_dict(d)
        pad = os.urandom(15)
        m = msg(150, 148)
        ks = hp_keystream(key, pad[:12], 148)
        wire = pad + bytes(a ^ b for a, b in zip(m, ks))
        r = classify(c, wire)
        self.assertEqual(r.kind, "init")
        self.assertEqual(r.body, m)

    def test_pre_handshake_counting(self):
        c = Config.from_dict(CFG)
        tags = parse_tags(CFG["i1"])
        i1 = bytes.fromhex("c0ffee") + os.urandom(4) + struct.pack(">I", int(time.time())) + b"abc" + b"12"
        stream = [dg(i1), dg(os.urandom(12)), dg(os.urandom(19)), dg(os.urandom(15) + msg(150, 148))]
        self.assertEqual(check_stream(c, stream, "initiator")["findings"], [])
        # one junk too many and one out of range
        bad = [dg(i1), dg(os.urandom(12)), dg(os.urandom(25)), dg(os.urandom(11)), dg(os.urandom(15) + msg(150, 148))]
        ids = {f["id"] for f in check_stream(c, bad, "initiator")["findings"]}
        self.assertEqual(ids, {"SPEC-PRE-COUNT", "SPEC-JUNK-SIZE"})

    def test_plain_wireguard_is_flagged(self):
        c = Config.from_dict({})
        stream = [dg(b"\x01\0\0\0" + os.urandom(144))]
        leaks = {l["id"] for l in check_stream(c, stream, "initiator")["leaks"]}
        self.assertIn("L1-WG-TYPE", leaks)
        self.assertIn("L2-WG-SIZE", leaks)


if __name__ == "__main__":
    unittest.main()
