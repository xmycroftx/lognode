#!/usr/bin/env python3
"""Report failed systemd units to LogNode.

Motivated by a real two-month outage: certbot.service failed twice a day since
July on a host that was shipping its journal to Grafana Cloud the entire time,
and nobody noticed. certbot.timer was ACTIVE and green throughout. A green timer
and a failing service look identical from a distance, and nothing in the fleet
was watching unit *results*.

Emits one line per failed unit, plus a heartbeat line every run. The heartbeat is
not decoration: without it, a watcher that has died is indistinguishable from a
fleet with nothing wrong -- which is precisely the failure this tool exists to
end. Silence must mean "the watcher is gone", never "all is well".
"""
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request

LOGNODE = os.environ.get("LOGNODE_URL", "http://127.0.0.1:9514/ingest")
INSTANCE = os.environ.get("UNITWATCH_INSTANCE", socket.gethostname())
TIMEOUT = 20


def _run(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
        return p.stdout
    except Exception as exc:
        print("unitwatch: %s failed: %s" % (" ".join(args), exc), file=sys.stderr)
        return ""


def _scope_units(user: bool):
    """-> [(unit, sub_state)] for units systemd currently considers failed."""
    args = ["systemctl"]
    if user:
        args.append("--user")
    args += ["list-units", "--state=failed", "--no-legend", "--plain", "--no-pager"]
    out = _run(args)
    units = []
    for line in out.splitlines():
        parts = line.split()
        # UNIT LOAD ACTIVE SUB DESCRIPTION...
        if len(parts) >= 4 and parts[0].endswith((".service", ".timer", ".mount",
                                                  ".socket", ".path", ".target")):
            units.append((parts[0], parts[3]))
    return units


def _result_of(unit: str, user: bool) -> str:
    args = ["systemctl"]
    if user:
        args.append("--user")
    args += ["show", "-p", "Result", "--value", unit]
    return (_run(args).strip() or "unknown")


def _kv(s: str) -> str:
    """logfmt-safe: no spaces, no quotes."""
    return str(s).replace(" ", "_").replace('"', "").replace("=", "-") or "-"


def main():
    lines = []
    total = 0

    for user in (False, True):
        scope = "user" if user else "system"
        # A user bus may not exist (no lingering session); that is not an error.
        units = _scope_units(user)
        for unit, sub in units:
            total += 1
            lines.append(
                "unitwatch unit=%s scope=%s active=failed sub=%s result=%s instance=%s"
                % (_kv(unit), scope, _kv(sub), _kv(_result_of(unit, user)), _kv(INSTANCE))
            )

    # Heartbeat last, so a reader sees the failures then the count that frames them.
    lines.append("unitwatch check=complete failed_count=%d instance=%s" % (total, _kv(INSTANCE)))

    # JSON with labels, the shape netsnap uses. The text/plain form carried the
    # instance only inside each line, so the alert parser could read it but the
    # stored row had no labels.instance and the traffic graph attributed every
    # heartbeat from every host to one "unknown" node -- 1,940 rows a day.
    payload = json.dumps({
        "lines": lines,
        "labels": {"instance": INSTANCE, "source": "unitwatch", "protocol": "http"},
    }).encode("utf-8")
    req = urllib.request.Request(LOGNODE, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status >= 300:
                print("unitwatch: %d failed unit(s), SEND HTTP %s" % (total, resp.status),
                      file=sys.stderr)
                return 1
    except Exception as exc:
        # Deliberately loud. A collector that cannot report its own failure to
        # collect is the exact bug this tool was written to stop repeating.
        print("unitwatch: %d failed unit(s), SEND FAILED %s: %s"
              % (total, type(exc).__name__, exc), file=sys.stderr)
        return 1

    if total:
        print("unitwatch: reported %d failed unit(s)" % total, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
