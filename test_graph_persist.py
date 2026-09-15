#!/usr/bin/env python3
"""Round-trip test for TrafficGraph snapshot persistence."""
import os
import tempfile
from pathlib import Path

STATE = Path(tempfile.mkdtemp()) / "graph.state.json"
os.environ["LOGNODE_GRAPH_STATE_FILE"] = str(STATE)

import graph as G  # noqa: E402  (must follow the env var)

G.GRAPH_STATE_FILE = STATE

ok = True


def check(label, cond):
    global ok
    print("  %-52s %s" % (label, "PASS" if cond else "FAIL"))
    if not cond:
        ok = False


# --- populate -------------------------------------------------------------
g1 = G.TrafficGraph()
declared_nodes = len(g1.nodes)
declared_edges = len(g1.edges)

ext_id = "external:203.0.113.99"
g1.add_node(G.FleetNode(ext_id, "203.0.113.99", "external", "203.0.113.99"))
g1.edges["e-ext"] = G.FleetEdge("e-ext", ext_id, "hub", "tcp", "port_22",
                                is_declared=False, total_volume=7,
                                total_bytes=1234, rate_1m=9.5,
                                baseline_15m=3.0, last_seen=1.0)
# also dirty a DECLARED edge's counters, if there is one
first_declared = next((e for e in g1.edges.values() if e.is_declared), None)
if first_declared:
    first_declared.total_volume = 4242

check("save_state() writes a file", g1.save_state() and STATE.exists())

# --- restore into a fresh instance ---------------------------------------
g2 = G.TrafficGraph()

check("external node restored", ext_id in g2.nodes)
check("external node kept its type", g2.nodes.get(ext_id) and g2.nodes[ext_id].type == "external")
check("undeclared edge restored", "e-ext" in g2.edges)
check("edge counters survived", g2.edges.get("e-ext") and g2.edges["e-ext"].total_volume == 7)
check("stale rate zeroed, not resurrected", g2.edges.get("e-ext") and g2.edges["e-ext"].rate_1m == 0.0)
check("baseline survived", g2.edges.get("e-ext") and g2.edges["e-ext"].baseline_15m == 3.0)
# Pick a declared node from whatever topology is configured rather than naming
# one: this test used to hardcode a hostname and failed anywhere else.
_sample = next(iter(g1.nodes), None)
check("declared nodes not duplicated",
      _sample is None or len([n for n in g2.nodes if n == _sample]) == 1)
check("declared node count unchanged (+1 external)", len(g2.nodes) == declared_nodes + 1)
if first_declared:
    check("declared edge kept definition but took history",
          g2.edges[first_declared.id].is_declared is True
          and g2.edges[first_declared.id].total_volume == 4242)

# --- corrupt snapshot must not take the process down ----------------------
STATE.write_text("{ this is not json")
g3 = G.TrafficGraph()
check("corrupt snapshot degrades to a clean start", len(g3.nodes) == declared_nodes)

# --- missing snapshot is simply a fresh graph -----------------------------
STATE.unlink()
g4 = G.TrafficGraph()
check("missing snapshot is a clean start", len(g4.nodes) == declared_nodes)

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
