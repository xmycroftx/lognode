#!/usr/bin/env python3
"""The schema is what we say it is, and retention cannot be misconfigured
into deleting everything.

No database. The DDL is asserted as text, because the thing that matters about
it -- that it can be run against a live production database at every boot
without changing anything -- is a property of the text.
"""
import re
from pathlib import Path

import schema as S

ok = True


def check(label, cond, detail=""):
    global ok
    print("  %-66s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        ok = False


# --- the DDL ---------------------------------------------------------------
creates = re.findall(r"CREATE\s+(?:TABLE|INDEX|EXTENSION)\b[^\n]*", S.SCHEMA)
check("every CREATE is IF NOT EXISTS (a no-op on the live database)",
      creates and all("IF NOT EXISTS" in c for c in creates), [c for c in creates if "IF NOT EXISTS" not in c])
for bad in ("DROP", "ALTER", "TRUNCATE", "DELETE"):
    check("schema contains no %s" % bad, not re.search(r"\b%s\b" % bad, S.SCHEMA))
check("eight indexes, as on the live table", S.SCHEMA.count("CREATE INDEX") + 1 == 8,
      S.SCHEMA.count("CREATE INDEX"))
for idx in ("idx_events_timestamp", "idx_events_event", "idx_events_event_time",
            "idx_events_instance_time", "idx_events_labels", "idx_events_kv",
            "idx_events_raw_trgm"):
    check("index %s is declared" % idx, idx in S.SCHEMA)
check("the trigram index needs pg_trgm, and the schema creates it",
      "CREATE EXTENSION IF NOT EXISTS pg_trgm" in S.SCHEMA)
check("timestamp keeps its now() default (callers may omit it)",
      re.search(r"timestamp\s+TIMESTAMPTZ\s+NOT NULL\s+DEFAULT now\(\)", S.SCHEMA) is not None)
sql_file = Path(__file__).resolve().parent / "schema.sql"
check("schema.sql exists beside the module", sql_file.exists())
if sql_file.exists():
    check("schema.sql is byte-identical to schema.SCHEMA (no second copy to drift)",
          sql_file.read_text() == S.SCHEMA)

# --- retention_window: the destructive knob ---------------------------------
check("7d", S.retention_window("7d") == 7 * 86400)
check("48h", S.retention_window("48h") == 48 * 3600)
check("90m", S.retention_window("90m") == 5400)
check("2w", S.retention_window("2w") == 14 * 86400)
check("case and whitespace tolerated", S.retention_window(" 14D ") == 14 * 86400)
for off in (None, "", "0", "off", "OFF", "none", "never"):
    check("%r means disabled" % (off,), S.retention_window(off) is None)
for bad in ("7", "30", "1x", "d7", "7 days", "-1d"):
    try:
        S.retention_window(bad)
        check("%r is refused" % bad, False, "accepted")
    except ValueError:
        check("%r is refused (unitless or malformed)" % bad, True)
for short in ("30m", "59m"):
    try:
        S.retention_window(short)
        check("%r is under the floor and refused" % short, False, "accepted")
    except ValueError:
        check("%r is under the floor and refused" % short, True)
check("exactly the floor is accepted", S.retention_window("60m") == 3600)

# --- the default ---------------------------------------------------------------
check("unset means the 30-day default, not forever",
      S.configured_window({}) == 30 * 86400, S.configured_window({}))
check("DEFAULT_RETENTION is itself a valid spec",
      S.retention_window(S.DEFAULT_RETENTION) == 30 * 86400)
check("an explicit off disables it", S.configured_window({"LOGNODE_RETENTION": "off"}) is None)
check("an explicit value overrides the default",
      S.configured_window({"LOGNODE_RETENTION": "7d"}) == 7 * 86400)
try:
    S.configured_window({"LOGNODE_RETENTION": "7"})
    check("a bad value raises at startup rather than falling back", False, "fell back")
except ValueError:
    check("a bad value raises at startup rather than falling back", True)

# --- retention_sql: bounded, parameterised, indexed -------------------------
sql = S.retention_sql(20000)
check("window is a bind parameter, not interpolated", "$1" in sql)
check("no percent or brace left from formatting", "%" not in sql and "{" not in sql)
check("bounded by LIMIT", "LIMIT 20000" in sql)
check("orders on timestamp so the index serves the batch", "ORDER BY timestamp" in sql)
check("deletes by ctid", "ctid" in sql)
check("only touches log_events", sql.count("log_events") == 2 and "findings" not in sql)
try:
    S.retention_sql(0)
    check("a zero batch is refused", False)
except ValueError:
    check("a zero batch is refused", True)

# --- the command tag parser ------------------------------------------------
check("DELETE 20000 -> 20000", S._rows_deleted("DELETE 20000") == 20000)
check("DELETE 0 -> 0", S._rows_deleted("DELETE 0") == 0)
check("garbage -> 0, not an exception", S._rows_deleted("") == 0)

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
