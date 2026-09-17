#!/usr/bin/env python3
"""Who is authenticated on which host, from where -- actors placed on hosts.

Built on the canonical auth events (see templates.json): auth_ssh_accepted
carries user + src_ip + host in one line, which is presence in a single record;
the sshd session open/close pair bounds the interval; auth_sudo_command is an
escalation within a session.

Interactive only. The PAM session events are ~90% cron and systemd-user -- a
root session every five minutes on every host -- which is automation, not an
actor. Those are filtered out here: a presence record is a human or an agent on
a host, the thing you would actually want to see or be warned about.

On a key-only fleet where a successful interactive login is rare, presence is a
tripwire: a user on a host that normally has none, or a known user from a source
never seen before, is exactly the high-signal event. new_presence() is that
diff; everything here is pure so it can be tested without a database.
"""
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# PAM services that are automation, not a person. A session under these is not
# presence; an interactive login (sshd) or an escalation (sudo/su) is.
_AUTOMATED_SERVICE = {"cron", "crond", "systemd-user", "systemd", "atd",
                      "anacron", "run-parts"}

# The interactive auth events we place on hosts.
_LOGIN = "auth_ssh_accepted"
_SESSION_OPEN = "auth_session_opened"
_SESSION_CLOSE = "auth_session_closed"
_SUDO = "auth_sudo_command"
_SUDO_FAIL = "auth_sudo_failed"


def _ts(value) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def parse_auth_event(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One stored log row -> a presence record, or None if it is not one.

    Returns {kind, host, user, src_ip, service, command, ts}. `kind` is
    login / session_open / session_close / sudo / sudo_fail. Non-interactive
    sessions (cron, systemd-user) return None -- they are automation.
    """
    event = ev.get("event") or ""
    kv = ev.get("kv") or {}
    host = (ev.get("labels") or {}).get("instance")
    ts = _ts(ev.get("timestamp"))
    if not host:
        return None

    if event == _LOGIN:
        user = kv.get("user")
        if not user:
            return None
        return {"kind": "login", "host": host, "user": user,
                "src_ip": kv.get("src_ip") or kv.get("ip"),
                "service": "sshd", "command": None, "ts": ts}

    if event in (_SESSION_OPEN, _SESSION_CLOSE):
        service = (kv.get("service") or "").lower()
        if service in _AUTOMATED_SERVICE:
            return None                       # cron/systemd -- not an actor
        user = kv.get("user")
        if not user:
            return None
        return {"kind": "session_open" if event == _SESSION_OPEN else "session_close",
                "host": host, "user": user, "src_ip": None,
                "service": service or None, "command": None, "ts": ts}

    if event in (_SUDO, _SUDO_FAIL):
        # sudo carries the invoker as `actor`; the target user landed in
        # target_host after normalisation (a known fields.py quirk), so read
        # both spellings rather than trust one.
        user = kv.get("actor")
        if not user:
            return None
        return {"kind": "sudo" if event == _SUDO else "sudo_fail",
                "host": host, "user": user, "src_ip": None, "service": "sudo",
                "command": kv.get("command"),
                "target": kv.get("target_user") or kv.get("target_host"), "ts": ts}

    return None


def build_presence(events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """-> {host: [principal, ...]}. A principal is one (user, src_ip) on a host.

    Logins define the principal and its source. Sessions and sudo are folded in
    by (host, user): a session has no src_ip of its own, so it attaches to that
    user's login-derived source on the same host. A user seen only via sudo or a
    session (no login row in the window) still appears, with src_ip unknown.
    """
    # (host, user) -> the source ip(s) that user logged in from, in this window
    login_src: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    principals: Dict[Tuple[str, str, Optional[str]], Dict[str, Any]] = {}

    recs = [r for r in (parse_auth_event(e) for e in events) if r]
    for r in recs:
        if r["kind"] == "login" and r["src_ip"]:
            login_src[(r["host"], r["user"])][r["src_ip"]] += 1

    def key(host, user, src_ip):
        return (host, user, src_ip)

    def principal(host, user, src_ip):
        k = key(host, user, src_ip)
        p = principals.get(k)
        if not p:
            p = {"host": host, "user": user, "src_ip": src_ip,
                 "logins": 0, "sessions_open": 0, "sessions_closed": 0,
                 "sudo": 0, "sudo_failed": 0, "methods": set(),
                 "first_seen": None, "last_seen": None}
            principals[k] = p
        return p

    def touch(p, ts):
        if ts is None:
            return
        p["first_seen"] = ts if p["first_seen"] is None else min(p["first_seen"], ts)
        p["last_seen"] = ts if p["last_seen"] is None else max(p["last_seen"], ts)

    for r in recs:
        host, user = r["host"], r["user"]
        if r["kind"] == "login":
            p = principal(host, user, r["src_ip"])
            p["logins"] += 1
            touch(p, r["ts"])
        else:
            # attach to the user's known source(s); if none, src_ip unknown
            srcs = list(login_src.get((host, user), {})) or [None]
            # a session/sudo with a single known source attaches there; with
            # several, attach to the most frequent so it lands on one principal
            src = max(login_src.get((host, user), {}), key=login_src[(host, user)].get) \
                if login_src.get((host, user)) else None
            p = principal(host, user, src)
            touch(p, r["ts"])
            if r["kind"] == "session_open":
                p["sessions_open"] += 1
            elif r["kind"] == "session_close":
                p["sessions_closed"] += 1
            elif r["kind"] == "sudo":
                p["sudo"] += 1
            elif r["kind"] == "sudo_fail":
                p["sudo_failed"] += 1

    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in principals.values():
        p["methods"] = sorted(p["methods"])
        # an unclosed session (or a login with no matching close) reads as still
        # present; a best-effort signal, not a guarantee.
        p["active"] = p["sessions_open"] > p["sessions_closed"] or (
            p["logins"] > 0 and p["sessions_closed"] == 0)
        out[p["host"]].append(p)
    for host in out:
        out[host].sort(key=lambda x: -(x["last_seen"] or 0))
    return dict(out)


def principal_keys(presence: Dict[str, List[Dict[str, Any]]]) -> set:
    """The set of (host, user, src_ip) triples present -- for diffing windows."""
    return {(p["host"], p["user"], p["src_ip"])
            for ps in presence.values() for p in ps}


def new_presence(recent: Dict[str, List[Dict[str, Any]]],
                 baseline: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Principals present in `recent` that the `baseline` window never saw.

    Two kinds, most-to-least alarming:
      new-host-user  -- a (host, user) pair with no history at all
      new-source     -- a known (host, user) but from a src_ip never seen

    The caller supplies the two windows (e.g. last 24h vs the prior 30 days).
    On a cold start the baseline is empty and everything is new once; that is
    the same "tell me what is here now" behaviour the graph takes on restart,
    not a bug. A login with an unknown src_ip (session-only, no login row) is
    NOT flagged as a new source -- absence of a source is not a new source.
    """
    base_triples = principal_keys(baseline)
    base_hostuser = {(h, u) for (h, u, _ip) in base_triples}

    findings = []
    for host, ps in recent.items():
        for p in ps:
            hu = (host, p["user"])
            trip = (host, p["user"], p["src_ip"])
            if trip in base_triples:
                continue
            if hu not in base_hostuser:
                kind = "new-host-user"
            elif p["src_ip"] is not None:
                kind = "new-source"
            else:
                continue          # known user, unknown source -> not a new source
            findings.append({"kind": kind, "host": host, "user": p["user"],
                             "src_ip": p["src_ip"], "logins": p["logins"],
                             "sudo": p["sudo"], "first_seen": p["first_seen"],
                             "last_seen": p["last_seen"]})
    # new-host-user before new-source; then most recent first
    findings.sort(key=lambda f: (f["kind"] != "new-host-user", -(f["last_seen"] or 0)))
    return findings
