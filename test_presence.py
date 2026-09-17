#!/usr/bin/env python3
"""Actors placed on hosts: presence from auth events, and the unexpected-login diff.

No database. Every function is pure on its event list. The cases that matter are
the negatives -- cron is not an actor, an unknown source is not a NEW source --
because a presence tripwire that cries on automation or on missing data is one
you learn to ignore, which defeats it.
"""
import presence as P

ok = True


def check(label, cond, detail=""):
    global ok
    print("  %-66s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        ok = False


def ev(event, ts, instance, **kv):
    return {"event": event, "timestamp": ts, "labels": {"instance": instance}, "kv": kv}


# --- parse: what is and isn't an actor ---------------------------------------
r = P.parse_auth_event(ev("auth_ssh_accepted", "2026-09-17T00:00:00Z", "hub",
                          user="mycroft", src_ip="192.0.2.21", method="publickey"))
check("ssh login parses to a login record", r and r["kind"] == "login"
      and r["user"] == "mycroft" and r["src_ip"] == "192.0.2.21" and r["host"] == "hub", r)
check("a cron PAM session is NOT an actor",
      P.parse_auth_event(ev("auth_session_opened", "t", "hub", user="root", service="cron")) is None)
check("a systemd-user session is NOT an actor",
      P.parse_auth_event(ev("auth_session_opened", "t", "hub", user="mycroft", service="systemd-user")) is None)
check("an sshd session IS an actor",
      (P.parse_auth_event(ev("auth_session_opened", "t", "hub", user="mycroft", service="sshd")) or {}).get("kind") == "session_open")
check("sudo parses with the invoker as user",
      (P.parse_auth_event(ev("auth_sudo_command", "t", "hub", actor="mycroft", command="/bin/ls")) or {}).get("user") == "mycroft")
check("a login with no user is not a record",
      P.parse_auth_event(ev("auth_ssh_accepted", "t", "hub", src_ip="192.0.2.21")) is None)
check("a non-auth event is not presence",
      P.parse_auth_event(ev("nginx_access", "t", "hub", ip="1.2.3.4")) is None)

# --- build: place actors on hosts --------------------------------------------
events = [
    ev("auth_ssh_accepted", 1000, "hub", user="mycroft", src_ip="192.0.2.21", method="publickey"),
    ev("auth_session_opened", 1001, "hub", user="mycroft", service="sshd"),
    ev("auth_sudo_command", 1002, "hub", actor="mycroft", command="/usr/sbin/wg show"),
    ev("auth_session_opened", 1500, "hub", user="root", service="cron"),   # noise
    ev("auth_ssh_accepted", 2000, "app-server", user="deploy", src_ip="198.51.100.9", method="publickey"),
    ev("auth_session_closed", 2100, "app-server", user="deploy", service="sshd"),
]
pres = P.build_presence(events)
check("two hosts have presence, cron ignored", set(pres) == {"hub", "app-server"}, set(pres))
og = pres["hub"][0]
check("hub principal is mycroft from the login source",
      og["user"] == "mycroft" and og["src_ip"] == "192.0.2.21", og)
check("the sudo folded onto mycroft's principal (no separate row)",
      len(pres["hub"]) == 1 and og["sudo"] == 1, pres["hub"])
check("the session open attached to the same principal", og["sessions_open"] == 1)
check("root/cron produced NO principal on hub",
      all(p["user"] != "root" for p in pres["hub"]))
check("mycroft with an open, unclosed session reads as active", og["active"] is True)
ap = pres["app-server"][0]
check("app-server deploy session is closed -> not active",
      ap["sessions_closed"] == 1 and ap["active"] is False, ap)
check("first/last seen span the records", og["first_seen"] == 1000 and og["last_seen"] == 1002)

# a user seen only via sudo (no login in window) still appears, source unknown
only_sudo = P.build_presence([ev("auth_sudo_command", 5, "vault-host", actor="svc", command="/bin/cat")])
check("a sudo-only user appears with src_ip unknown",
      only_sudo["vault-host"][0]["src_ip"] is None and only_sudo["vault-host"][0]["sudo"] == 1)

# --- new_presence: the tripwire ----------------------------------------------
baseline = P.build_presence([
    ev("auth_ssh_accepted", 100, "hub", user="mycroft", src_ip="192.0.2.21", method="publickey"),
])
recent_same = P.build_presence([
    ev("auth_ssh_accepted", 200, "hub", user="mycroft", src_ip="192.0.2.21", method="publickey"),
])
check("a known user from a known source raises nothing",
      P.new_presence(recent_same, baseline) == [])

recent_newsrc = P.build_presence([
    ev("auth_ssh_accepted", 300, "hub", user="mycroft", src_ip="203.0.113.66", method="publickey"),
])
ns = P.new_presence(recent_newsrc, baseline)
check("a known user from a NEW source is flagged",
      len(ns) == 1 and ns[0]["kind"] == "new-source" and ns[0]["src_ip"] == "203.0.113.66", ns)

recent_newhost = P.build_presence([
    ev("auth_ssh_accepted", 400, "app-server", user="mycroft", src_ip="192.0.2.21", method="publickey"),
])
nh = P.new_presence(recent_newhost, baseline)
check("a user on a host never seen before is flagged, and ranks first",
      len(nh) == 1 and nh[0]["kind"] == "new-host-user" and nh[0]["host"] == "app-server", nh)

check("cold start: everything is new once (empty baseline)",
      len(P.new_presence(recent_same, {})) == 1)
check("a session-only principal with unknown source is NOT a new-source alert",
      P.new_presence(P.build_presence([
          ev("auth_session_opened", 9, "hub", user="mycroft", service="sshd")]), baseline) == [])
check("ordering: new-host-user before new-source",
      [f["kind"] for f in P.new_presence(P.build_presence([
          ev("auth_ssh_accepted", 1, "newbox", user="a", src_ip="1.1.1.1"),
          ev("auth_ssh_accepted", 2, "hub", user="mycroft", src_ip="9.9.9.9")]), baseline)]
      == ["new-host-user", "new-source"])

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
