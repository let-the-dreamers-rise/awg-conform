# awg-conform

Cross-implementation conformance and detectability tests for **AmneziaWG**, the
WireGuard-based anti-censorship VPN protocol used by Amnezia VPN and many
third-party clients in Russia, Iran, Myanmar and elsewhere.

AmneziaWG changed four times in 18 months (1.0, 1.5, 2.0, 3.x), and several
independent implementations now exist. When one drifts from the spec, users
either cannot connect to servers built on another implementation, or send
traffic a censor can single out. This repository checks both.

## What it does

1. Starts a client and a server, each from any implementation under test, in
   two Linux network namespaces joined by a veth pair.
2. Brings the tunnel up, sends ICMP through it (small and 1100-byte packets),
   and captures every UDP datagram on the wire.
3. Checks the capture against a model written from the published parameter
   reference (`awgconform/spec.py`), not from any one implementation:
   - **Conformance:** I1-I5 signature packets match their tag templates;
     exactly Jc junk datagrams, sized within [Jmin, Jmax]; S1-S4 padding and
     H1-H4 header ranges; header protection (AWG 3).
   - **Detectability:** leftovers a passive DPI box can key on: plain
     WireGuard type bytes, stock WireGuard sizes, constant byte offsets,
     a visible packet counter, transport lengths stuck on one residue mod 16.
4. Writes `out/REPORT.md` and `out/matrix.json`.

## Implementations under test (pinned in `scripts/build-impls.sh`)

| name | project | language |
|---|---|---|
| amneziawg-go | amnezia-vpn/amneziawg-go (reference) | Go |
| amnezia-box-go | hoaxisr/amneziawg-go (used by amnezia-box, a sing-box fork) | Go |
| awgtun | AYastrebov/awgtun | Rust |
| gotatun-awg | okhsunrog/gotatun, AmneziaWG fork of Mullvad's GotaTun | Rust |

Planned: the official Linux kernel module, the MikroTik `awg-proxy` (C), and
mihomo's fork (metacubex/amneziawg-go).

## Run

```sh
sudo AWG_BIN=/opt/awg/bin ./scripts/build-impls.sh
python3 -m unittest discover -s tests
sudo AWG_BIN=/opt/awg/bin python3 -m awgconform.matrix --out out
```

Needs root (network namespaces, TUN), `tcpdump`, `iproute2`, `ping`, Go 1.25,
Rust 1.97 and `python3-cryptography`.

## Disclosure

Security-relevant findings go to the maintainers privately first and are
published here only after they agree or 90 days pass.

## License

MIT
