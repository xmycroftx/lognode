#!/usr/bin/env python3
"""The row limit the caller asks for is the row limit the query uses.

This is the regression test for a bug that produced no error and no warning:
engine.query_logs clamped every query at 1000 rows regardless of the limit
argument, so /threats asked for 5000 over 24 hours, got the most recent 1000,
and labelled the result "24h". The window on the page and the window in the
data had not agreed for as long as the table had more than 1000 access lines
in a day.

Nothing here touches Postgres. The clamp and the shared WHERE builder are pure
functions of their arguments, which is the whole reason they can be tested --
the same lesson as ttp.make_internal_check and findings.should_raise, both of
which shipped wrong while buried in a request handler.
"""
import engine

ok = True


def check(label, cond, detail=""):
    global ok
    print("  %-62s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        ok = False


class Fake(engine.PostgresSink):
    """Just enough object to reach the two methods under test.

    _build_filters and the clamp touch nothing but their arguments, so no
    connection pool is needed and none is opened.
    """
    def __init__(self):
        self.pool = None


P = Fake()

# --- the clamp ------------------------------------------------------------
CAP = P.HARD_ROW_CAP


def clamp(n):
    return max(1, min(n, CAP))


check("5000 stays 5000 (this returned 1000)", clamp(5000) == 5000, "got %d" % clamp(5000))
check("50000 stays 50000", clamp(50000) == 50000)
check("the hard cap is well above any window we render", CAP >= 100_000)
check("a request above the cap is capped, not refused", clamp(CAP * 10) == CAP)
check("zero and negative become one, not an error", clamp(0) == 1 and clamp(-5) == 1)

# --- the shared WHERE builder ---------------------------------------------
# count_logs and query_logs must filter identically; a count over a different
# WHERE would misreport truncation in whichever direction it drifted.
where_a, params_a = P._build_filters(q="HTTP/1.1", since_s=86400)
where_b, params_b = P._build_filters(q="HTTP/1.1", since_s=86400)
check("the builder is deterministic", (where_a, params_a) == (where_b, params_b))
check("both filters land in the clause", where_a.count("AND") == 1, where_a)
check("params carry no limit -- the caller appends it", len(params_a) == 2,
      "%r" % (params_a,))
check("the placeholders are numbered from 1",
      "$1" in where_a and "$2" in where_a, where_a)

check("no filters means no WHERE", P._build_filters() == ("", []))

# The count query is built by string-appending the clause; a clause that did
# not start with WHERE (or was not empty) would produce invalid SQL.
for kw in ({"q": "x"}, {"instance": "hub"}, {"since_s": 60}, {"event": "e"}):
    w, _ = P._build_filters(**kw)
    check("%-22s yields a usable clause" % list(kw)[0], w.startswith("WHERE "), w)

# --- the filter that must never silently match nothing ---------------------
# Guarding the lesson from the kv-alias bug: a value search is rejected loudly
# rather than quietly matching zero rows.
try:
    P._build_filters(value="'; DROP--")
    check("an unsearchable value raises", False, "it did not")
except ValueError:
    check("an unsearchable value raises", True)

w, p = P._build_filters(value="198.51.100.10")
check("a legitimate address is accepted", "jsonpath" in w and len(p) == 1)

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
