"""Run client/server implementation pairs in network namespaces, capture the
wire traffic between them, and check it against the spec.

usage: sudo python3 -m awgconform.run [--client NAME] [--server NAME] [--config FILE] [--out DIR]
"""

import argparse
import json
import os
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from . import impls
from .checks import check_stream
from .pcap import read_udp
from .spec import Config

NS_C, NS_S = "awgc", "awgs"
VETH_C, VETH_S = "veth-awgc", "veth-awgs"
IP_C, IP_S = "10.99.0.1", "10.99.0.2"
TUN_C, TUN_S = "10.100.0.1", "10.100.0.2"
PORT_C, PORT_S = 51821, 51820


def sh(*cmd, check=True, **kw):
    return subprocess.run(cmd, check=check, capture_output=True, text=True, **kw)


def keypair():
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv.hex(), pub.hex()


def netns_up():
    netns_down()
    sh("ip", "netns", "add", NS_C)
    sh("ip", "netns", "add", NS_S)
    sh("ip", "link", "add", VETH_C, "type", "veth", "peer", "name", VETH_S)
    sh("ip", "link", "set", VETH_C, "netns", NS_C)
    sh("ip", "link", "set", VETH_S, "netns", NS_S)
    for ns, dev, ip in ((NS_C, VETH_C, IP_C), (NS_S, VETH_S, IP_S)):
        sh("ip", "-n", ns, "addr", "add", ip + "/24", "dev", dev)
        sh("ip", "-n", ns, "link", "set", dev, "up")
        sh("ip", "-n", ns, "link", "set", "lo", "up")


def netns_down():
    for ns in (NS_C, NS_S):
        sh("ip", "netns", "del", ns, check=False)
    for d in impls.UAPI_DIRS:
        for name in ("awgc0", "awgs0"):
            p = os.path.join(d, name + ".sock")
            if os.path.exists(p):
                os.unlink(p)


def wait_if(ns, ifname, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        if sh("ip", "-n", ns, "link", "show", ifname, check=False).returncode == 0:
            return
        time.sleep(0.1)
    raise RuntimeError(f"{ifname} did not appear in {ns}")


def run_pair(client, server, awg, out_dir, pings=20, big_pings=200):
    os.makedirs(out_dir, exist_ok=True)
    ci, si = impls.IMPLS[client], impls.IMPLS[server]
    cpriv, cpub = keypair()
    spriv, spub = keypair()
    ifc, ifs = "awgc0", "awgs0"
    result = {"client": client, "server": server, "config": awg}
    procs = []
    netns_up()
    pcap = os.path.join(out_dir, "wire.pcap")
    td = subprocess.Popen(["ip", "netns", "exec", NS_C, "tcpdump", "-U", "-n", "-i", VETH_C, "-w", pcap, "udp"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.5)
        procs.append(impls.start(si, NS_S, ifs, awg, os.path.join(out_dir, "server.log")))
        procs.append(impls.start(ci, NS_C, ifc, awg, os.path.join(out_dir, "client.log")))
        wait_if(NS_S, ifs)
        wait_if(NS_C, ifc)
        impls.configure(si, ifs, spriv, PORT_S, awg, {"public_key": cpub, "allowed_ip": TUN_C + "/32"})
        impls.configure(ci, ifc, cpriv, PORT_C, awg,
                        {"public_key": spub, "allowed_ip": TUN_S + "/32", "endpoint": f"{IP_S}:{PORT_S}"})
        for ns, dev, ip in ((NS_C, ifc, TUN_C), (NS_S, ifs, TUN_S)):
            sh("ip", "-n", ns, "addr", "add", ip + "/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "mtu", "1280", "up")
        p = sh("ip", "netns", "exec", NS_C, "ping", "-c", str(pings), "-i", "0.2", "-W", "2", TUN_S, check=False)
        result["ping_ok"] = " 0% packet loss" in p.stdout or (", 0 received" not in p.stdout and p.returncode == 0)
        result["ping_summary"] = [l for l in p.stdout.splitlines() if "packet loss" in l]
        # bulk: large packets, to exercise transport classification and padding
        if result["ping_ok"] and big_pings:
            b = sh("ip", "netns", "exec", NS_C, "ping", "-c", str(big_pings), "-i", "0.01", "-s", "1100",
                   "-W", "1", TUN_S, check=False)
            result["bulk_summary"] = [l for l in b.stdout.splitlines() if "packet loss" in l]
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
    finally:
        time.sleep(0.5)
        for pr in procs:
            pr.terminate()
        for pr in procs:
            try:
                pr.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pr.kill()
        td.terminate()
        td.wait(timeout=5)
        netns_down()
    dg = read_udp(pcap) if os.path.exists(pcap) else []
    cfg = Config.from_dict(awg)
    c2s = [d for d in dg if d.src == IP_C]
    s2c = [d for d in dg if d.src == IP_S]
    result["client_stream"] = check_stream(cfg, c2s, "initiator")
    result["server_stream"] = check_stream(cfg, s2c, "responder")
    with open(os.path.join(out_dir, "result.json"), "w") as f:
        json.dump(result, f, indent=2)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", default="amneziawg-go")
    ap.add_argument("--server", default="amneziawg-go")
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    with open(a.config) as f:
        awg = json.load(f)
    r = run_pair(a.client, a.server, awg, a.out)
    json.dump({k: r[k] for k in r if k != "config"}, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
