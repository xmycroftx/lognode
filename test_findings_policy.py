#!/usr/bin/env python3
"""What reaches a human, and what must not.

The negative cases matter more than the positive ones here: a queue that raises
noise stops being read, which is the whole failure this module was built to
avoid. Two of these assertions encode findings #8 and #9 -- real false positives
that a live triage pass had to dismiss.
"""
import findings as F

ok = True


def check(label, cond, detail=""):
    global ok
    print("  %-58s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        ok = False


def actor(techniques=None, score=0, inconsistency=0):
    return {"techniques": techniques or {}, "score": score,
            "inconsistency": inconsistency}


# --- one occurrence is enough for credential/execution attempts ------------
for t in ("ssrf-metadata", "rce-attempt", "private-key-theft"):
    check("single %s raises" % t, bool(F.should_raise(actor({t: 1}))))

# --- enumeration needs quantity -------------------------------------------
# This is finding #8 and #9 exactly: one /wp-login.php, raised, then dismissed.
check("a single cms-probe does NOT raise (finding #8/#9)",
      F.should_raise(actor({"cms-probe": 1})) == "",
      "got=%r" % F.should_raise(actor({"cms-probe": 1})))
check("a single webshell-probe does NOT raise",
      F.should_raise(actor({"webshell-probe": 1})) == "")
check("two webshell-probes still do not raise",
      F.should_raise(actor({"webshell-probe": 2})) == "")
check("three webshell-probes do raise",
      bool(F.should_raise(actor({"webshell-probe": 3}))))
check("the reason names the count",
      "x3" in F.should_raise(actor({"webshell-probe": 3})))

# --- the other two doors ---------------------------------------------------
check("deception at the floor raises",
      bool(F.should_raise(actor({"recon": 1}, inconsistency=40))))
check("deception below the floor does not",
      F.should_raise(actor({"recon": 1}, inconsistency=39)) == "")
check("score at the floor raises",
      bool(F.should_raise(actor({"recon": 1}, score=40))))
check("score below the floor does not",
      F.should_raise(actor({"recon": 1}, score=39)) == "")

# --- silence is the default ------------------------------------------------
check("an actor doing nothing notable is silent",
      F.should_raise(actor({"recon": 5, "unknown": 3})) == "")
check("an empty actor is silent", F.should_raise(actor()) == "")

# --- credential attempts outrank enumeration in the reason -----------------
reason = F.should_raise(actor({"ssrf-metadata": 1, "cms-probe": 9}))
check("the reason leads with the serious technique", reason.startswith("attempted"),
      "got=%r" % reason)

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
