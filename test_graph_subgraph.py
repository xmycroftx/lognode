#!/usr/bin/env python3
"""Neighbourhood traversal: identifier folding, hop distance, and dangling edges."""
import graph as G

ok = True


def check(label, cond):
    global ok
    print("  %-52s %s" % (label, "PASS" if cond else "FAIL"))
    if not cond:
        ok = False


def fresh():
    g = G.TrafficGraph.__new__(G.TrafficGraph)
    g.nodes, g.edges, g.shifts, g.ip_to_node = {}, {}, {}, {}
    for nid, ip, typ in (("hub", "10.0.0.1", "server"),
                         ("a", "10.0.0.2", "workstation"),
                         ("b", "10.0.0.3", "workstation"),
                         ("far", "10.0.0.4", "server")):
        n = G.FleetNode(nid, nid, typ, ip, ips=[ip])
        g.add_node(n)
    def edge(s, t):
        g.edges[f"{s}->{t}"] = G.FleetEdge(f"{s}->{t}", s, t, "tcp", "port_22",
                                           is_declared=False, total_volume=3)
    edge("a", "hub"); edge("hub", "b"); edge("b", "far")
    return g


# --- hop distance -----------------------------------------------------------
g = fresh()
r1 = g.subgraph("hub", depth=1)
check("depth=1 reaches direct neighbours only", {n["id"] for n in r1["nodes"]} == {"hub", "a", "b"})
check("seed is hop 0", [n for n in r1["nodes"] if n["id"] == "hub"][0]["hops"] == 0)
check("neighbours are hop 1", all(n["hops"] == 1 for n in r1["nodes"] if n["id"] != "hub"))

r2 = g.subgraph("hub", depth=2)
check("depth=2 reaches two hops", {n["id"] for n in r2["nodes"]} == {"hub", "a", "b", "far"})
check("far node is hop 2", [n for n in r2["nodes"] if n["id"] == "far"][0]["hops"] == 2)

# --- traversal is undirected ------------------------------------------------
# 'a' only ever appears as an edge SOURCE; reachability must not depend on that.
check("traverses edges in both directions", "a" in {n["id"] for n in g.subgraph("hub", 1)["nodes"]})

# --- identifier folding -----------------------------------------------------
check("resolves by IP", g.subgraph("10.0.0.1", 1)["resolved"] == "hub")
check("resolves by node id", g.subgraph("hub", 1)["resolved"] == "hub")

# --- unknown seed is an answer, not an error --------------------------------
r = g.subgraph("203.0.113.9", 1)
check("unknown address -> found=False, no exception", r["found"] is False and r["nodes"] == [])

# --- edges are confined to the returned nodes -------------------------------
ids = {n["id"] for n in r1["nodes"]}
check("no edge escapes the node set",
      all(e["source"] in ids and e["target"] in ids for e in r1["edges"]))

# --- dangling edges: the bug this traversal found ---------------------------
g2 = fresh()
g2.edges["ghost"] = G.FleetEdge("ghost", "hub", "external:198.51.100.7", "tcp", "x",
                                is_declared=False, total_volume=1)
r3 = g2.subgraph("hub", depth=1)          # must not raise KeyError
check("subgraph survives a dangling edge", "external:198.51.100.7" not in {n["id"] for n in r3["nodes"]})
dropped = g2.prune_dangling_edges()
check("prune_dangling_edges removes it", dropped == ["ghost"] and "ghost" not in g2.edges)
check("prune leaves healthy edges alone", len(g2.edges) == 3)

# --- depth is clamped -------------------------------------------------------
check("absurd depth is clamped, not fatal", g.subgraph("hub", depth=999)["depth"] <= 6)

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
