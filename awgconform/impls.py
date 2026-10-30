"""How to start and configure each implementation under test.

Every implementation is started inside a network namespace with a TUN
interface. Implementations that speak the cross-platform UAPI get their
whole config over the UNIX socket; GotaTun's AmneziaWG fork takes the
obfuscation parameters as environment variables.
"""

import os
import socket
import subprocess
import time
from dataclasses import dataclass

BIN = os.environ.get("AWG_BIN", "/opt/awg/bin")

UAPI_DIRS = ("/var/run/amneziawg", "/var/run/wireguard")

# UAPI keys that only exist in AWG 3.x
V3_KEYS = {"header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout",
           "reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers",
           "disable_cookies"}
GOTATUN_KEYS = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
                "i1", "i2", "i3", "i4", "i5"}


@dataclass
class Impl:
    name: str
    binary: str
    style: str             # "uapi" or "env"
    supports_v3: bool = True
    notes: str = ""
    extra_args: tuple = ()

    def path(self):
        return os.path.join(BIN, self.binary)


IMPLS = {
    "amneziawg-go": Impl("amneziawg-go", "awg-go-official", "uapi", notes="amnezia-vpn/amneziawg-go (reference)"),
    "amnezia-box-go": Impl("amnezia-box-go", "awg-go-hoaxisr", "uapi", notes="hoaxisr/amneziawg-go (amnezia-box / sing-box fork)"),
    "awgtun": Impl("awgtun", "awgtun-cli", "uapi", notes="AYastrebov/awgtun (Rust)",
                   extra_args=("--disable-drop-privileges",)),
    "gotatun-awg": Impl("gotatun-awg", "gotatun", "env", supports_v3=False, notes="okhsunrog/gotatun AmneziaWG fork (Rust)",
                        extra_args=("--disable-drop-privileges",)),
}


def find_sock(ifname, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        for d in UAPI_DIRS:
            p = os.path.join(d, ifname + ".sock")
            if os.path.exists(p):
                return p
        time.sleep(0.1)
    raise RuntimeError(f"UAPI socket for {ifname} did not appear")


def uapi_set(sock_path, lines):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.sendall(("set=1\n" + "".join(l + "\n" for l in lines) + "\n").encode())
    buf = b""
    while b"\n\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    txt = buf.decode(errors="replace")
    if "errno=0" not in txt:
        raise RuntimeError(f"UAPI set failed: {txt.strip()}")


def start(impl: Impl, netns: str, ifname: str, awg: dict, log_path: str):
    env = dict(os.environ)
    env.setdefault("LOG_LEVEL", "error")
    args = ["ip", "netns", "exec", netns, impl.path(), "-f", *impl.extra_args, ifname]
    if impl.style == "env":
        for k, v in awg.items():
            if k in GOTATUN_KEYS:
                env["AWG_" + k.upper()] = str(v)
    log = open(log_path, "w")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
    return proc


def configure(impl: Impl, ifname: str, private_key_hex: str, port: int, awg: dict, peer: dict):
    lines = [f"private_key={private_key_hex}", f"listen_port={port}"]
    if impl.style == "uapi":
        for k, v in awg.items():
            if k in V3_KEYS and not impl.supports_v3:
                continue
            if isinstance(v, bool):
                v = "true" if v else "false"
            lines.append(f"{k}={v}")
    lines += [f"public_key={peer['public_key']}", "replace_allowed_ips=true", f"allowed_ip={peer['allowed_ip']}"]
    if peer.get("endpoint"):
        lines.append(f"endpoint={peer['endpoint']}")
    uapi_set(find_sock(ifname), lines)
