#!/usr/bin/env python3
"""Point-in-time socket snapshot: which process is talking to which address.

execve auditing tells you WHAT RAN. This tells you WHO IT TALKED TO. Neither
answers "which binary opened a connection to which IP" on its own; together they
do, and that is the question worth answering for security.

Deliberately a periodic SNAPSHOT rather than syscall auditing:

  * `-a always,exit -S connect` catches every connect() including the thousands
    of short-lived ones, at a volume that would dominate the pipeline.
  * a snapshot every N seconds costs one `ss` invocation and a handful of lines,
    and still catches anything that holds a socket open long enough to matter --
    which is what a C2 channel, an exfil transfer or a long-poll all do.

Short-lived connections are missed by design. That trade is the point.

Emits logfmt so the templatizer learns ONE template for every line, and so
fields.py canonicalises local/peer into *_ip and *_port automatically.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

LOGNODE = os.environ.get("LOGNODE_URL", "http://127.0.0.1:9514/ingest")
INSTANCE = os.environ.get("NETSNAP_INSTANCE", socket.gethostname())

# ss -tunpH:  Netid State Recv-Q Send-Q Local:Port Peer:Port [users:(("proc",pid=N,fd=M))]
RE_USERS = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
# loopback and link-local chatter is noise for this purpose
SKIP_PEER = re.compile(r"^(127\.|::1|0\.0\.0\.0|\[::\]|\*|169\.254\.)")


def split_addr(a: str):
    """'127.0.0.1:9514' or '[::1]:22' -> (host, port)."""
    a = a.strip()
    if a.startswith("["):
        host, _, port = a.rpartition("]:")
        return host.lstrip("["), port
    host, _, port = a.rpartition(":")
    return host, port


def snapshot(include_listen=False):
    """-> list of dicts, one per established (or listening) socket."""
    args = ["ss", "-tunpH"]
    args.append("state" if include_listen else "state")
    args.append("all" if include_listen else "established")
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=15).stdout
    except Exception as e:
        print("netsnap: ss failed: %s" % e, file=sys.stderr)
        return []

    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < (6 if include_listen else 5):
            continue
        # Column count depends on the filter: `state established` makes ss OMIT
        # the State column, so the fields shift left by one. Reading parts[1] as
        # state gave "state=0" -- that was Recv-Q.
        netid = parts[0]
        if include_listen:
            state, local, peer = parts[1], parts[4], parts[5]
        else:
            state, local, peer = "established", parts[3], parts[4]
        peer_host, peer_port = split_addr(peer)
        local_host, local_port = split_addr(local)
        # ss appends the interface to link-scoped addresses: 198.51.100.10%enp6s0
        local_host = local_host.split("%")[0]
        peer_host = peer_host.split("%")[0]
        if SKIP_PEER.match(peer_host) or not peer_port or peer_port == "*":
            continue
        m = RE_USERS.search(line)
        proc = m.group(1) if m else "-"
        pid = m.group(2) if m else "-"
        rows.append({
            "proto": netid, "state": state,
            "local": local_host, "local_port": local_port,
            "peer": peer_host, "peer_port": peer_port,
            "process": proc, "pid": pid,
        })
    return rows


def to_line(r):
    # logfmt: one stable shape, so the templatizer learns a single rule for it
    return ("netsnap proto=%(proto)s state=%(state)s local=%(local)s "
            "local_port=%(local_port)s peer=%(peer)s peer_port=%(peer_port)s "
            "process=%(process)s pid=%(pid)s" % r)


def ship(lines, dry_run=False, to_stdout=False):
    if not lines:
        return 0, "no sockets"
    if to_stdout:
        # Journal mode. On hosts with no route to LogNode -- the public droplets
        # are not on the WireGuard mesh -- we print instead, systemd captures it,
        # and the Alloy already running there ships it onward. No new network
        # path, no firewall change, no WireGuard peer.
        for l in lines:
            print(l, flush=True)
        return len(lines), "journal"
    if dry_run:
        for l in lines:
            print("  " + l)
        return len(lines), "dry-run"
    payload = json.dumps({
        "lines": lines,
        "labels": {"instance": INSTANCE, "source": "netsnap", "protocol": "http"},
    }).encode()
    req = urllib.request.Request(LOGNODE, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return len(lines), "HTTP %s" % resp.status
    except Exception as e:
        # Do NOT swallow this. A collector that cannot report its own failure to
        # collect is the exact bug that hid a 20-minute outage on the Mac.
        return 0, "SEND FAILED %s: %s" % (type(e).__name__, e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=0,
                    help="seconds between snapshots; 0 = run once and exit")
    ap.add_argument("--listen", action="store_true", help="include listening sockets")
    ap.add_argument("--dry-run", action="store_true", help="print, do not send")
    ap.add_argument("--stdout", action="store_true",
                    help="print to stdout for journald/Alloy to collect, instead of POSTing")
    a = ap.parse_args()

    while True:
        rows = snapshot(include_listen=a.listen)
        n, status = ship([to_line(r) for r in rows], dry_run=a.dry_run, to_stdout=a.stdout)
        if a.dry_run or "FAILED" in status:
            print("netsnap: %d sockets, %s" % (n, status), flush=True)
        if not a.interval:
            return 0 if "FAILED" not in status else 1
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
