#!/usr/bin/env python3
"""Exercise retire_transient_externals against the cases the rule was specified in."""
import time
import graph as G

OLD = time.time() - 7200      # 2h -> past the 1h TTL
NEW = time.time() - 60        # 1m -> inside the TTL


def fresh():
    g = G.TrafficGraph.__new__(G.TrafficGraph)
    g.nodes, g.edges, g.shifts = {}, {}, {}
    g.ip_to_node = {}
    g.add_node(G.FleetNode("hub", "hub", "server", "127.0.0.1"))
    g.add_node(G.FleetNode("laptop", "laptop", "workstation", "192.0.2.21"))
    return g


def ext(g, ip, age):
    n = G.FleetNode(f"external:{ip}", ip, "external", ip)
    n.last_seen = age
    n.metadata["first_seen"] = age
    g.add_node(n)
    return n.id


def edge(g, a, b, volume):
    eid = f"{a}->{b}"
    g.edges[eid] = G.FleetEdge(eid, a, b, "tcp", "port_22",
                               is_declared=False, total_volume=volume)


cases = []

# 1. one-off, old, one internal neighbour  -> RETIRE
g = fresh(); n = ext(g, "1.1.1.1", OLD); edge(g, n, "hub", 1)
cases.append(("one-off / old / 1 node", g, n, True))

# 2. same node twice -> KEEP  ("more than once on the same node = stays")
g = fresh(); n = ext(g, "2.2.2.2", OLD); edge(g, n, "hub", 2)
cases.append(("twice / old / 1 node", g, n, False))

# 3. one hit each against two internal nodes -> KEEP ("2 nodes = stays")
g = fresh(); n = ext(g, "3.3.3.3", OLD)
edge(g, n, "hub", 1); edge(g, n, "laptop", 0)
cases.append(("once / old / 2 nodes", g, n, False))

# 4. one-off but young -> KEEP (not yet judgeable)
g = fresh(); n = ext(g, "4.4.4.4", NEW); edge(g, n, "hub", 1)
cases.append(("one-off / young / 1 node", g, n, False))

# 5. orphan external, old, no edges at all -> RETIRE
g = fresh(); n = ext(g, "5.5.5.5", OLD)
cases.append(("orphan / old / 0 edges", g, n, True))

# 6. an INTERNAL node, old and silent -> never retired
g = fresh(); g.nodes["hub"].last_seen = OLD
cases.append(("internal / old / silent", g, "hub", False))

ok = True
for name, g, node_id, should_go in cases:
    retired = g.retire_transient_externals()
    gone = node_id not in g.nodes
    verdict = "PASS" if gone == should_go else "FAIL"
    if verdict == "FAIL":
        ok = False
    print("  %-28s expect=%-6s got=%-6s  %s"
          % (name, "retire" if should_go else "keep",
             "retired" if gone else "kept", verdict))
    # edges must go with the node
    if gone:
        leftovers = [e for e in g.edges.values()
                     if e.source == node_id or e.target == node_id]
        if leftovers:
            print("      FAIL: %d orphaned edge(s) left behind" % len(leftovers))
            ok = False

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
