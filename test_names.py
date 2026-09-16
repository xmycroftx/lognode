#!/usr/bin/env python3
"""No module references a name that does not exist.

This exists because of a specific bug. The escalation policy was moved out of
server.py into findings.py, and the edit removed a contiguous range that also
contained FINDING_SWEEP_SECONDS. The constant was referenced exactly once,
inside a loop, so nothing failed at import: the module loaded, the sweep task
started, completed one pass, then died with a NameError visible only in the
journal. The triage queue stopped running for a day and nothing said so.

Every other test here asserts behaviour. This one asserts that the code can
run at all, which no amount of behavioural testing covers -- the dead branch
was never reached by any test because it needed a live server and a timer.
"""
import subprocess
import sys

MODULES = ["server.py", "engine.py", "findings.py", "ecs.py", "schema.py", "behaviour.py",
           "ttp.py", "graph.py", "fields.py", "enrich.py", "alert.py",
           "mcp_server.py", "netsnap.py", "unitwatch.py", "loki_tail.py"]

try:
    import pyflakes  # noqa: F401
except ImportError:
    print("  pyflakes not installed -- cannot check for undefined names.")
    print("  Install it (uv run --with pyflakes) or this class of bug ships again.")
    print("  ---", "SKIPPED (not a pass)")
    raise SystemExit(0)

proc = subprocess.run([sys.executable, "-m", "pyflakes", *MODULES],
                      capture_output=True, text=True)

# Only undefined names. Unused imports and star-imports are style; a name that
# does not exist is a crash waiting for the right code path.
bad = [l for l in (proc.stdout + proc.stderr).splitlines()
       if "undefined name" in l.lower()]

for line in bad:
    print("  FAIL %s" % line)
if not bad:
    print("  %-62s PASS" % "no undefined names in any module")

print("  ---", "ALL PASS" if not bad else "FAILURES PRESENT")
raise SystemExit(0 if not bad else 1)
