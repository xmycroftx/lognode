#!/usr/bin/env python3
"""
LogNode Fleet Traffic Graph Model & Topology Shift Detector
============================================================
"Thinking in Graphs" domain engine for fleet telemetry.
Models nodes (hosts, services, gateways, cloud) and directed communication edges
(HTTP telemetry ingest, Loki journald streams, SSH sessions, DNS queries, Postgres flushes).

Continuously computes sliding 1m/15m flow rates and detects topological shifts:
- SILENT_LINK: Expected active link drops to 0 traffic (> 120s stale).
- NOVEL_EDGE: Traffic observed along an undeclared or unmapped network path.
- FLOW_SURGE: Edge rate surges > 4σ above rolling 15m baseline.
- STARVATION: Established edge drops > 80% below baseline.
"""

import socket
import os
import json
from pathlib import Path
import dataclasses
import time
import math
import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set


# Cloud services sit behind rotating load-balancer addresses: logs-prod-042
# resolved to 98.88.39.197 while prometheus-prod-66 answered 98.85.154.20 one
# minute and 98.91.9.120 the next. Keying the graph on those addresses mints a
# fresh external:* node every time one rotates.
#
# Reverse DNS is useless here -- they PTR to ec2-98-88-39-197.compute-1.amazonaws
# .com, which identifies AWS, not Grafana. So resolve FORWARD from the hostnames
# we already know from the Alloy config, and fold the answers into one node.
CLOUD_HOSTS: Dict[str, List[str]] = {
    "grafana-cloud": [
        "logs-prod-042.grafana.net",
        "prometheus-prod-66-prod-us-east-3.grafana.net",
        "fleet-management-prod-028.grafana.net",
    ],
}
CLOUD_REFRESH_SECONDS = 600

# How long a one-off external address stays on the wall before it becomes
# eligible to be aged out. Long enough that a slow scan spread over several
# minutes still accumulates a second observation and survives.
EXTERNAL_TTL_SECONDS = 3600

# Declared topology. Ships as topology.example.json; point this at your own.
TOPOLOGY_FILE = Path(os.environ.get(
    "LOGNODE_TOPOLOGY_FILE", str(Path(__file__).resolve().parent / "topology.json")))

# Snapshot of the observed graph. The declared topology is rebuilt from code at
# every start; this file carries only what was LEARNED -- external nodes, edge
# counters, and open shifts -- so a restart does not blank the wall. Same place
# and same spirit as templates.runtime.json, and gitignored for the same reason.
GRAPH_STATE_FILE = Path(os.environ.get(
    "LOGNODE_GRAPH_STATE_FILE",
    str(Path(__file__).resolve().parent / "graph.state.json")))

# Snapshot cadence. The periodic check runs every 15s; writing that often would
# be pointless churn for a graph this size.
GRAPH_SAVE_SECONDS = 60

@dataclass
class FleetNode:
    id: str
    name: str
    type: str  # workstation, server, service, gateway, cloud, client, external
    ip: Optional[str] = None
    ips: List[str] = field(default_factory=list)
    role: str = ""
    status: str = "HEALTHY"  # HEALTHY, DEGRADED, OFFLINE, UNKNOWN
    last_seen: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        all_ips = list(self.ips) if self.ips else ([self.ip] if self.ip else [])
        if self.ip and self.ip not in all_ips:
            all_ips.insert(0, self.ip)
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "ip": self.ip,
            "ips": all_ips,
            "role": self.role,
            "status": self.status,
            "last_seen": round(self.last_seen, 2),
            "metadata": self.metadata
        }


def format_bytes_rate(bytes_per_sec: float) -> str:
    if bytes_per_sec >= 1_048_576:
        return f"{bytes_per_sec / 1_048_576:.1f} MB/s"
    elif bytes_per_sec >= 1024:
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    elif bytes_per_sec > 0:
        return f"{bytes_per_sec:.0f} B/s"
    return "0 B/s"


def format_rate_1m(rate: float) -> str:
    if rate >= 1000:
        return f"{rate / 1000:.1f}k/m"
    return f"{rate:.0f}/m"


@dataclass
class FleetEdge:
    id: str
    source: str
    target: str
    protocol: str
    channel: str
    is_declared: bool = True
    expected_min_rate: float = 0.0  # expected msgs/min for critical telemetry links
    total_volume: int = 0
    total_bytes: int = 0
    rate_1m: float = 0.0
    bytes_1m: int = 0
    bytes_per_sec: float = 0.0
    baseline_15m: float = 0.0
    last_seen: float = 0.0
    status: str = "HEALTHY"  # HEALTHY, SURGING, STARVED, SILENT, NOVEL
    metadata: Dict[str, Any] = field(default_factory=dict)
    _samples: deque = field(default_factory=deque, repr=False)  # (timestamp, bytes)

    def record(self, count: int = 1, byte_count: int = 0, ts: Optional[float] = None):
        now = ts or time.time()
        self.total_volume += count
        self.total_bytes += byte_count
        self.last_seen = now
        bytes_per_unit = max(1, byte_count // count) if count > 0 and byte_count > 0 else (byte_count if count == 0 else 128)
        for _ in range(count):
            self._samples.append((now, bytes_per_unit))

    def prune(self, now: float):
        cutoff = now - 900  # 15 minutes
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()

    def update_rates(self, now: float, graph_uptime: float):
        self.prune(now)
        cutoff_1m = now - 60
        count_1m = 0
        bytes_1m = 0
        for t, b in self._samples:
            if t >= cutoff_1m:
                count_1m += 1
                bytes_1m += b

        self.rate_1m = float(count_1m)
        self.bytes_1m = bytes_1m
        self.bytes_per_sec = round(bytes_1m / 60.0, 2)

        window_mins = min(max(graph_uptime / 60.0, 1.0), 15.0)
        self.baseline_15m = round(len(self._samples) / window_mins, 2)

    def get_stroke_width(self) -> int:
        """
        Dynamically widens lines (1px to 10px) based on bandwidth (BW) of logs
        per measurement period.
        """
        if self.status == "SILENT" or (self.rate_1m == 0 and self.bytes_per_sec == 0):
            return 1

        if self.bytes_per_sec > 0:
            # Bandwidth-based logarithmic scaling:
            # <= 100 B/s: 1-2px, ~1 KB/s: 3px, ~10 KB/s: 5px, ~100 KB/s: 7px, ~500 KB/s: 8px, >= 1 MB/s: 10px
            w = round(1 + math.log10(max(10.0, self.bytes_per_sec) / 10.0) * 1.8)
            return max(1, min(10, w))
        elif self.rate_1m > 0:
            # Rate-based logarithmic scaling:
            w = round(1 + math.log10(max(1.0, self.rate_1m)) * 2.2)
            return max(1, min(10, w))
        return 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "protocol": self.protocol,
            "channel": self.channel,
            "is_declared": self.is_declared,
            "expected_min_rate": self.expected_min_rate,
            "total_volume": self.total_volume,
            "total_bytes": self.total_bytes,
            "rate_1m": self.rate_1m,
            "bytes_1m": self.bytes_1m,
            "bytes_per_sec": self.bytes_per_sec,
            "stroke_width": self.get_stroke_width(),
            "baseline_15m": self.baseline_15m,
            "last_seen": round(self.last_seen, 2) if self.last_seen else 0,
            "status": self.status,
            "metadata": self.metadata
        }


@dataclass
class TopologyShift:
    id: str
    type: str  # SILENT_LINK, NOVEL_EDGE, FLOW_SURGE, STARVATION
    source: str
    target: str
    severity: str  # critical, warning, notice, info
    message: str
    rate_1m: float
    baseline_15m: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "source": self.source,
            "target": self.target,
            "severity": self.severity,
            "message": self.message,
            "rate_1m": self.rate_1m,
            "baseline_15m": self.baseline_15m,
            "timestamp": round(self.timestamp, 2)
        }


class TrafficGraph:
    """
    Fleet domain traffic graph.
    Maintains active nodes, directed communication edges, computes real-time
    topological shift alerts, and exposes GraphQL-friendly query dictionaries and Mermaid flows.
    """

    def __init__(self, check_interval: int = 15):
        self.check_interval = check_interval
        self.start_time = time.time()
        self.nodes: Dict[str, FleetNode] = {}
        self.edges: Dict[str, FleetEdge] = {}
        self.shifts: Dict[str, TopologyShift] = {}
        self.ip_to_node: Dict[str, str] = {}
        self._alert_cooldowns: Dict[str, float] = {}
        self.anomaly_detector: Optional[Any] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None

        self._last_cloud_refresh = 0.0
        self._last_state_save = 0.0
        # Node id representing the host running LogNode itself. Flows observed
        # in ingested logs are attributed to its service nodes, so it cannot be
        # a hardcoded hostname without tying the engine to one fleet. Overridden
        # by "self" in the topology file.
        self.self_node = os.environ.get("LOGNODE_SELF_NODE", "lognode-host")
        self._init_declared_topology()
        # After the declared topology, so a snapshot tops it up instead of
        # racing it.
        self.load_state()

    @property
    def is_armed(self) -> bool:
        if self.anomaly_detector:
            return getattr(self.anomaly_detector, "is_armed", False)
        return False

    def _init_declared_topology(self):
        """Load the declared topology -- the nodes and flows you assert SHOULD
        exist -- from a config file.

        This used to be 39 hardcoded declarations in this method, which made the
        engine unusable by anyone whose fleet was not this fleet, and baked one
        site's addresses and hostnames into the source. Observed traffic is
        matched against whatever is declared here; an address that matches
        nothing becomes external:<ip>.

        A missing file is not an error. The graph then declares nothing and every
        observation is external, which is a legitimate way to run it: watch first,
        declare once you know what normal looks like.
        """
        path = TOPOLOGY_FILE
        if not path.exists():
            print(f"[TrafficGraph] no topology file at {path} -- "
                  "starting with nothing declared; all peers will be external")
            return

        try:
            with open(path) as fh:
                data = json.load(fh)
        except Exception as exc:
            # Refuse to guess. Loading half a topology would silently mark real
            # fleet members as strangers, which is worse than declaring none.
            print(f"[TrafficGraph] topology file {path} is unreadable ({exc}) -- "
                  "starting with nothing declared")
            return

        self.self_node = data.get("self", self.self_node)

        n_ok = e_ok = 0
        for raw in data.get("nodes", []):
            try:
                ip = raw.get("ip")
                ips = list(raw.get("ips") or [])
                if ip and ip not in ips:
                    ips.insert(0, ip)
                self.add_node(FleetNode(
                    raw["id"], raw.get("name") or raw["id"], raw.get("type", "server"),
                    ip, ips=ips, role=raw.get("role", "")))
                n_ok += 1
            except Exception as exc:
                print(f"[TrafficGraph] skipping bad node entry {raw!r}: {exc}")

        for raw in data.get("edges", []):
            try:
                self._declare_edge(raw["source"], raw["target"],
                                   raw.get("protocol", "tcp"),
                                   raw.get("channel", "default"),
                                   expected_min_rate=float(raw.get("expected_min_rate", 0.0)))
                e_ok += 1
            except Exception as exc:
                print(f"[TrafficGraph] skipping bad edge entry {raw!r}: {exc}")

        print(f"[TrafficGraph] declared topology: {n_ok} nodes, {e_ok} edges from {path.name}")

    def _declare_edge(self, source: str, target: str, protocol: str, channel: str, expected_min_rate: float = 0.0):
        src_id = self.resolve_node_id(source)
        tgt_id = self.resolve_node_id(target)
        edge_id = f"{src_id}->{tgt_id}:{protocol}"
        self.edges[edge_id] = FleetEdge(
            id=edge_id,
            source=src_id,
            target=tgt_id,
            protocol=protocol,
            channel=channel,
            is_declared=True,
            expected_min_rate=expected_min_rate
        )

    def add_node(self, node: FleetNode):
        self.nodes[node.id] = node
        if node.ip:
            self.ip_to_node[node.ip] = node.id
        for ip_addr in node.ips:
            self.ip_to_node[ip_addr] = node.id

    def resolve_node_id(self, identifier: str) -> str:
        """
        Disambiguates multi-IP machines and maps IPs, hostnames, and IP:port
        combinations to canonical FleetNode IDs (e.g. 10.0.0.5 and 192.0.2.17 -> one host).
        """
        if not identifier:
            return "unknown"
        clean = identifier.strip()

        # 1. Direct node match
        if clean in self.nodes:
            return clean

        # 2. Direct IP lookup
        if clean in self.ip_to_node:
            return self.ip_to_node[clean]

        # 3. IP:port or host:port handling
        if ":" in clean:
            host_part, port_part = clean.split(":", 1)
            canonical_host = self.ip_to_node.get(host_part, host_part)

            PORT_TO_SERVICE = {
                "9514": "lognode",
                "5432": "postgres",
                "12346": "alloy",
                "53": "dnsmasq",
                "11434": "ollama",
                "22": "sshd",
            }
            svc_name = PORT_TO_SERVICE.get(port_part)
            if svc_name:
                svc_node_id = f"{canonical_host}:{svc_name}"
                if svc_node_id in self.nodes:
                    return svc_node_id

            if canonical_host in self.nodes:
                candidate = f"{canonical_host}:{port_part}"
                if candidate in self.nodes:
                    return candidate
                return canonical_host

            if host_part in self.ip_to_node:
                return self.ip_to_node[host_part]

        return clean

    def get_or_create_node(self, node_id: str, default_type: str = "client", ip: Optional[str] = None) -> FleetNode:
        canonical_id = self.resolve_node_id(node_id)
        if canonical_id not in self.nodes:
            name = canonical_id.split(":")[-1] if ":" in canonical_id else canonical_id
            node_ip = ip or (canonical_id if "." in canonical_id else None)
            new_node = FleetNode(
                id=canonical_id,
                name=f"{default_type}:{name}",
                type=default_type,
                ip=node_ip,
                ips=[node_ip] if node_ip else [],
                role=f"Dynamically discovered {default_type}",
                status="HEALTHY",
                metadata={"discovered": True}
            )
            self.add_node(new_node)
        return self.nodes[canonical_id]

    def record_flow(
        self,
        source: str,
        target: str,
        protocol: str = "http",
        channel: str = "traffic",
        count: int = 1,
        byte_count: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Records traffic observed along a directed edge (source -> target)."""
        now = time.time()
        source_id = self.resolve_node_id(source)
        target_id = self.resolve_node_id(target)

        # Ensure nodes exist
        src_node = self.get_or_create_node(source_id)
        tgt_node = self.get_or_create_node(target_id, default_type="service")
        src_node.last_seen = now
        tgt_node.last_seen = now

        edge_id = f"{source_id}->{target_id}:{protocol}"
        edge = self.edges.get(edge_id)
        if not edge:
            # Novel edge detected
            edge = FleetEdge(
                id=edge_id,
                source=source_id,
                target=target_id,
                protocol=protocol,
                channel=channel,
                is_declared=False,
                expected_min_rate=0.0,
                status="NOVEL",
                metadata=metadata or {}
            )
            self.edges[edge_id] = edge

        edge.record(count=count, byte_count=byte_count, ts=now)

    def observe_log(
        self,
        instance: str,
        event: str,
        labels: Optional[Dict[str, str]] = None,
        kv: Optional[Dict[str, Any]] = None,
        raw: str = "",
        byte_count: int = 0
    ):
        """
        Domain extraction logic mapping incoming fleet telemetry logs to graph flows.
        """
        lbls = labels or {}
        key_vals = kv or {}
        b_count = byte_count if byte_count > 0 else (len(raw.encode("utf-8")) if raw else 128)

        # 1. Main Telemetry Ingest Stream Edge: instance -> <self>:lognode
        src_raw = instance or lbls.get("instance", "unknown")
        src_host = self.resolve_node_id(src_raw)
        proto = lbls.get("protocol")
        if not proto:
            if lbls.get("job") == "loki.source.journal.host" or "journal" in str(lbls):
                proto = "loki"
            else:
                proto = "http"

        channel = lbls.get("source") or lbls.get("job") or "telemetry_ingest"
        self.record_flow(source=src_host, target=f"{self.self_node}:lognode", protocol=proto, channel=channel, count=1, byte_count=b_count)

        # 1b. Socket snapshots (netsnap): process <-> peer, point-in-time.
        # This is the only source that attributes a flow to a PROCESS rather than
        # just a host. resolve_node_id() maps known addresses back to fleet nodes,
        # so internal peers appear as named hosts and only genuinely foreign
        # addresses create external:* nodes -- which keeps the graph readable
        # instead of sprouting a node per ephemeral peer.
        if event.startswith("netsnap") or lbls.get("source") == "netsnap":
            proc = key_vals.get("process")
            peer_ip = key_vals.get("peer_ip") or key_vals.get("ip")
            peer_port = key_vals.get("peer_port")
            if proc and proc != "-" and peer_ip:
                src_proc = f"{src_host}:{proc}"
                resolved_peer = self.resolve_node_id(peer_ip)
                if resolved_peer == peer_ip:          # unknown to the fleet
                    resolved_peer = f"external:{peer_ip}"

                # Direction matters, and so does which port names the SERVICE.
                # For an outbound connection the peer port is the service port
                # (443, 9100). For an INBOUND one the peer port is ephemeral, so
                # keying the channel on it mints a brand new edge per client
                # connection and the graph grows without bound. Pick the lower
                # port as the service, and orient the edge accordingly.
                try:
                    lp = int(key_vals.get("local_port") or 0)
                    pp = int(peer_port or 0)
                except ValueError:
                    lp = pp = 0
                proto = key_vals.get("proto") or "tcp"
                if pp and (lp == 0 or pp <= lp):
                    # we connected out to peer:pp
                    a, b, svc = src_proc, resolved_peer, pp
                else:
                    # peer connected in to us:lp
                    a, b, svc = resolved_peer, src_proc, lp
                self.record_flow(
                    source=a, target=b, protocol=proto,
                    channel=f"port_{svc}" if svc else "socket",
                    count=1, byte_count=b_count,
                )
            return

        # 2. Remote SSH Access Flow: client_ip -> host:sshd
        if event in ("publickey_accepted", "sshd_session", "sshd") or "Accepted publickey" in raw:
            client_ip = key_vals.get("ip")
            if not client_ip:
                import re
                m = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", raw)
                if m:
                    client_ip = m.group(1)

            if client_ip:
                resolved_client = self.resolve_node_id(client_ip)
                target_host = src_host if src_host != "unknown" else self.self_node
                target_ssh = f"{target_host}:sshd" if ":" not in target_host else target_host
                self.record_flow(source=resolved_client, target=target_ssh, protocol="ssh", channel="remote_access", count=1, byte_count=b_count)

        # 3. DNS Resolution Flow: client_ip -> <self>:dnsmasq -> external:domain
        if event in ("query_result", "dnsmasq") or "dnsmasq" in lbls.get("unit", ""):
            client_ip = key_vals.get("ip") or key_vals.get("client")
            domain = key_vals.get("url") or key_vals.get("domain") or key_vals.get("query")
            if client_ip:
                resolved_client = self.resolve_node_id(client_ip)
                self.record_flow(source=resolved_client, target=f"{self.self_node}:dnsmasq", protocol="dns", channel="dns_query", count=1, byte_count=b_count)
            if domain:
                ext_target = f"external:{domain}"
                self.record_flow(source=f"{self.self_node}:dnsmasq", target=ext_target, protocol="dns", channel="dns_upstream", count=1, byte_count=b_count)

    def record_internal_metric(self, source: str, target: str, protocol: str, channel: str, count: int = 1, byte_count: int = 0):
        """Helper to register internal pipeline events (Postgres flush, Alloy scrape, LLM synthesis)."""
        b_count = byte_count if byte_count > 0 else count * 256
        self.record_flow(source=source, target=target, protocol=protocol, channel=channel, count=count, byte_count=b_count)

    def evaluate_shifts(self):
        """
        Evaluates graph edges against baseline flow patterns and flags topological shifts:
        - SILENT_LINK
        - NOVEL_EDGE
        - FLOW_SURGE
        - STARVATION
        """
        now = time.time()
        uptime = now - self.start_time
        active_shifts: Dict[str, TopologyShift] = {}

        for edge_id, edge in list(self.edges.items()):
            edge.update_rates(now, uptime)
            baseline = edge.baseline_15m
            rate = edge.rate_1m

            # 1. Dead Link / Silent Flow Detector
            # For declared links with expected volume, detect when flow ceases
            if edge.is_declared and edge.expected_min_rate > 0:
                if edge.total_volume > 0:
                    silence_duration = now - edge.last_seen
                    if silence_duration > 120.0 and rate == 0:
                        edge.status = "SILENT"
                        shift_id = f"silent:{edge_id}"
                        active_shifts[shift_id] = TopologyShift(
                            id=shift_id,
                            type="SILENT_LINK",
                            source=edge.source,
                            target=edge.target,
                            severity="critical" if edge.expected_min_rate >= 2.0 else "warning",
                            message=f"Traffic on link {edge.id} silent for {int(silence_duration)}s (nominal baseline: {baseline:.1f} logs/min).",
                            rate_1m=rate,
                            baseline_15m=baseline,
                            timestamp=now
                        )
                        continue

            # 2. Novel Edge Detector
            if not edge.is_declared:
                edge.status = "NOVEL"
                shift_id = f"novel:{edge_id}"
                active_shifts[shift_id] = TopologyShift(
                    id=shift_id,
                    type="NOVEL_EDGE",
                    source=edge.source,
                    target=edge.target,
                    severity="warning",
                    message=f"Undeclared communication path active: {edge.source} -> {edge.target} via {edge.protocol} ({rate:.1f} logs/min).",
                    rate_1m=rate,
                    baseline_15m=baseline,
                    timestamp=now
                )

            # 3. Flow Surge Detector (4-sigma & >= 2.5x baseline)
            if rate >= 30.0 and baseline > 0:
                std = max(math.sqrt(baseline), 1.0)
                z_score = (rate - baseline) / std
                if z_score >= 4.0 and rate >= (baseline * 2.5):
                    edge.status = "SURGING"
                    shift_id = f"surge:{edge_id}"
                    active_shifts[shift_id] = TopologyShift(
                        id=shift_id,
                        type="FLOW_SURGE",
                        source=edge.source,
                        target=edge.target,
                        severity="warning",
                        message=f"Edge {edge.id} surging at {rate:.0f} logs/min (+{z_score:.1f}σ vs {baseline:.1f}/min baseline).",
                        rate_1m=rate,
                        baseline_15m=baseline,
                        timestamp=now
                    )
                    continue

            # 4. Flow Starvation Detector (> 80% drop from heavy baseline)
            if baseline >= 20.0 and rate < (0.2 * baseline) and (now - edge.last_seen <= 120.0):
                edge.status = "STARVED"
                shift_id = f"starvation:{edge_id}"
                active_shifts[shift_id] = TopologyShift(
                    id=shift_id,
                    type="STARVATION",
                    source=edge.source,
                    target=edge.target,
                    severity="notice",
                    message=f"Edge {edge.id} starved: current rate {rate:.0f}/min is >80% below baseline {baseline:.1f}/min.",
                    rate_1m=rate,
                    baseline_15m=baseline,
                    timestamp=now
                )
                continue

            # If no anomalies triggered and link is declared, return to HEALTHY
            if edge.is_declared:
                edge.status = "HEALTHY"

        self.shifts = active_shifts

        # Update node status based on edge health
        for node in self.nodes.values():
            node_edges = [e for e in self.edges.values() if e.source == node.id or e.target == node.id]
            if any(e.status == "SILENT" for e in node_edges if e.expected_min_rate >= 2.0):
                node.status = "DEGRADED"
            elif any(e.status == "SURGING" for e in node_edges):
                node.status = "SURGING"
            else:
                node.status = "HEALTHY"

    # ---- persistence -------------------------------------------------------
    #
    # Only LEARNED state is written. Declared nodes and edges are rebuilt from
    # _init_declared_topology() on every start, so persisting their definitions
    # would let a stale snapshot override the code -- the bug where the map
    # silently outranks the territory. For declared things we keep the counters
    # and drop the definition.

    @staticmethod
    def _public_fields(obj) -> dict:
        """Serialisable dataclass fields: no leading underscore, no deque."""
        out = {}
        for f in dataclasses.fields(obj):
            if f.name.startswith("_"):
                continue
            v = getattr(obj, f.name)
            if isinstance(v, deque):
                continue
            out[f.name] = v
        return out

    def save_state(self, path: Optional[Path] = None) -> bool:
        path = path or GRAPH_STATE_FILE
        try:
            payload = {
                "version": 1,
                "saved_at": time.time(),
                # external nodes only -- the ones nobody declared
                "nodes": [self._public_fields(n) for n in self.nodes.values()
                          if n.type == "external"],
                # every declared node's last_seen, so silence is measured from
                # when it was really last heard, not from process start
                "node_seen": {n.id: n.last_seen for n in self.nodes.values()
                              if n.type != "external"},
                "edges": [self._public_fields(e) for e in self.edges.values()],
                "shifts": [self._public_fields(sh) for sh in self.shifts.values()],
            }
            tmp = path.with_suffix(path.suffix + ".tmp")
            with open(tmp, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp, path)          # atomic: never a half-written snapshot
            return True
        except Exception as exc:
            print(f"[TrafficGraph] state save failed: {exc}")
            return False

    def load_state(self, path: Optional[Path] = None) -> bool:
        """Restore a snapshot over the freshly declared topology."""
        path = path or GRAPH_STATE_FILE
        if not path.exists():
            return False
        try:
            with open(path) as fh:
                payload = json.load(fh)
        except Exception as exc:
            print(f"[TrafficGraph] state load failed, starting clean: {exc}")
            return False

        node_fields = {f.name for f in dataclasses.fields(FleetNode)}
        edge_fields = {f.name for f in dataclasses.fields(FleetEdge)}
        shift_fields = {f.name for f in dataclasses.fields(TopologyShift)}

        restored_nodes = restored_edges = 0

        for raw in payload.get("nodes", []):
            data = {k: v for k, v in raw.items() if k in node_fields}
            if not data.get("id") or data["id"] in self.nodes:
                continue
            try:
                self.add_node(FleetNode(**data))
                restored_nodes += 1
            except Exception:
                continue

        for node_id, seen in (payload.get("node_seen") or {}).items():
            node = self.nodes.get(node_id)
            if node:
                node.last_seen = max(node.last_seen, seen)

        for raw in payload.get("edges", []):
            data = {k: v for k, v in raw.items() if k in edge_fields}
            eid = data.get("id")
            if not eid:
                continue
            existing = self.edges.get(eid)
            if existing is not None:
                # Declared edge: keep the code's definition, take the history.
                for attr in ("total_volume", "total_bytes", "baseline_15m", "last_seen"):
                    if attr in data:
                        setattr(existing, attr, data[attr])
                continue
            try:
                edge = FleetEdge(**data)
            except Exception:
                continue
            # Rates describe a rolling window that is now stale; the samples
            # deque was deliberately not persisted, so zero them rather than
            # present an hour-old rate as current.
            edge.rate_1m = 0.0
            edge.bytes_1m = 0
            edge.bytes_per_sec = 0.0
            self.edges[eid] = edge
            restored_edges += 1

        for raw in payload.get("shifts", []):
            data = {k: v for k, v in raw.items() if k in shift_fields}
            sid = data.get("id")
            if not sid or sid in self.shifts:
                continue
            try:
                self.shifts[sid] = TopologyShift(**data)
            except Exception:
                continue

        age = time.time() - payload.get("saved_at", 0)
        print(f"[TrafficGraph] restored {restored_nodes} external node(s), "
              f"{restored_edges} edge(s), {len(self.shifts)} shift(s) "
              f"from a snapshot {age / 60:.1f} min old")
        return True

    def retire_transient_externals(self, now: Optional[float] = None) -> List[str]:
        """Age out external addresses that turned out to be nothing.

        A node is retired only when ALL THREE of these hold:

          * it has been observed at most once (total volume across its edges <= 1),
          * it has been on the graph longer than EXTERNAL_TTL_SECONDS,
          * it touches at most one internal node.

        Any one of them failing keeps it, and that is the whole point of the
        rule: a second hit on the SAME node is a repeat visitor, and a single
        hit against TWO internal nodes is a sweep. Both are more interesting
        than one packet from one stranger, not less -- so neither is ever aged
        out, however old it gets.

        Only "external" nodes are considered. Declared fleet members are never
        retired, however quiet they go, because their silence is the signal.
        """
        now = now or time.time()
        retired: List[str] = []

        for node_id, node in list(self.nodes.items()):
            if node.type != "external":
                continue

            # Nodes created before this field existed fall back to last_seen.
            first_seen = node.metadata.setdefault("first_seen", node.last_seen)
            if (now - first_seen) <= EXTERNAL_TTL_SECONDS:
                continue                       # too young to judge

            edges = [e for e in self.edges.values()
                     if e.source == node_id or e.target == node_id]

            if sum(e.total_volume for e in edges) > 1:
                continue                       # seen more than once -- keep

            neighbours = {(e.target if e.source == node_id else e.source)
                          for e in edges}
            internal = {n for n in neighbours
                        if n in self.nodes and self.nodes[n].type != "external"}
            if len(internal) > 1:
                continue                       # touched 2+ internal nodes -- keep

            self.nodes.pop(node_id, None)
            for eid in [e for e, edge in self.edges.items()
                        if edge.source == node_id or edge.target == node_id]:
                self.edges.pop(eid, None)
                self.shifts.pop("novel:" + eid, None)
            retired.append(node_id)

        return retired

    def _resolve_cloud_ips_blocking(self) -> Dict[str, str]:
        """DNS is blocking, so this runs in a worker thread. -> {ip: node_id}"""
        found: Dict[str, str] = {}
        for node_id, hostnames in CLOUD_HOSTS.items():
            if node_id not in self.nodes:
                continue
            for hostname in hostnames:
                try:
                    for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                        found[info[4][0]] = node_id
                except Exception:
                    continue          # transient DNS failure: keep what we have
        return found

    async def refresh_cloud_ips(self, force: bool = False):
        """Fold rotating cloud load-balancer addresses into their fleet node."""
        now = time.time()
        if not force and (now - self._last_cloud_refresh) < CLOUD_REFRESH_SECONDS:
            return
        self._last_cloud_refresh = now
        try:
            resolved = await asyncio.to_thread(self._resolve_cloud_ips_blocking)
        except Exception:
            return
        if not resolved:
            return

        for ip, node_id in resolved.items():
            if self.ip_to_node.get(ip) != node_id:
                self.ip_to_node[ip] = node_id
                node = self.nodes.get(node_id)
                if node and ip not in node.ips:
                    node.ips.append(ip)

        # Retire any external:<ip> node we created before the mapping existed,
        # and the edges pointing at it -- otherwise the stale ones linger forever
        # next to the correctly-attributed traffic.
        for ip, node_id in resolved.items():
            stale = f"external:{ip}"
            if stale in self.nodes:
                self.nodes.pop(stale, None)
                for eid in [e for e, edge in self.edges.items()
                            if edge.source == stale or edge.target == stale]:
                    self.edges.pop(eid, None)
                    self.shifts.pop(f"novel:{eid}", None)

    def start(self):
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._periodic_check())

    def stop(self):
        self._running = False
        self.save_state()          # a clean shutdown should not lose the wall
        if self._task:
            self._task.cancel()

    async def _periodic_check(self):
        while self._running:
            try:
                await asyncio.sleep(self.check_interval)
                await self.refresh_cloud_ips()
                orphaned = self.prune_dangling_edges()
                if orphaned:
                    print("[TrafficGraph] dropped %d edge(s) with a missing "
                          "endpoint: %s" % (len(orphaned), ", ".join(orphaned[:5])))
                retired = self.retire_transient_externals()
                if retired:
                    names = ", ".join(sorted(retired)[:8])
                    print("[TrafficGraph] aged out %d transient external node(s): %s"
                          % (len(retired), names))
                self.evaluate_shifts()
                if (time.time() - self._last_state_save) >= GRAPH_SAVE_SECONDS:
                    self._last_state_save = time.time()
                    self.save_state()
                if self.is_armed:
                    await self._dispatch_shift_alerts()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[TrafficGraph] Error in periodic check: {e}")

    async def _dispatch_shift_alerts(self):
        try:
            from alert import dispatch_discord_alert
        except ImportError:
            return

        now = time.time()
        for shift in self.shifts.values():
            if shift.severity == "critical":
                last_alert = self._alert_cooldowns.get(shift.id, 0)
                if now - last_alert > 300:  # 5 min cooldown
                    self._alert_cooldowns[shift.id] = now
                    asyncio.create_task(dispatch_discord_alert(
                        title=f"Topology Shift: {shift.type}",
                        description=shift.message,
                        severity="critical",
                        instance=shift.source,
                        event="topology_shift",
                        spike_info=f"{shift.rate_1m:.0f}/m vs {shift.baseline_15m:.1f}/m baseline"
                    ))

    def to_dict(self) -> Dict[str, Any]:
        """GraphQL-friendly full graph schema output."""
        return {
            "uptime_seconds": round(time.time() - self.start_time, 1),
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "active_shifts": len(self.shifts),
                "fleet_status": "DEGRADED" if any(s.severity == "critical" for s in self.shifts.values()) else "HEALTHY"
            },
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "shifts": [s.to_dict() for s in self.shifts.values()]
        }

    def get_shifts(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.shifts.values()]

    def prune_dangling_edges(self) -> List[str]:
        """Drop edges whose endpoints are no longer nodes.

        Found by the subgraph traversal, which died on
        KeyError: 'external:140.82.114.34' -- an edge outliving the node it
        pointed at. Retirement paths (cloud-address folding, transient-external
        aging) remove a node and its edges together, so the likely source is an
        edge recorded for an address that never got a node of its own. Either
        way the graph should not carry an edge to something that does not exist:
        it inflates edge counts, draws phantom links in the Mermaid output, and
        turns any traversal into a landmine.
        """
        dropped = []
        for eid, edge in list(self.edges.items()):
            if edge.source not in self.nodes or edge.target not in self.nodes:
                self.edges.pop(eid, None)
                self.shifts.pop(f"novel:{eid}", None)
                dropped.append(eid)
        return dropped

    def subgraph(self, identifier: str, depth: int = 1) -> Dict[str, Any]:
        """The connected neighbourhood around an address, host, or node id.

        "Which IP is this" and "what does it talk to" were two separate
        questions: /query?ip= answers the first against the log index, this
        answers the second against the topology. Same identifier resolution as
        everything else -- resolve_node_id() folds a host's several addresses onto
        one node -- so an address found in the logs can be pasted straight in.

        Breadth-first to `depth` hops, edges traversed in BOTH directions:
        "who did this address talk to" is not a question about who dialled.
        """
        raw = (identifier or "").strip()
        seed = self.resolve_node_id(raw)

        # An address nobody declared is still a real answer: netsnap mints
        # external:<ip> for exactly this case, so look for that spelling too.
        if seed not in self.nodes and raw:
            for cand in (f"external:{raw}", raw):
                if cand in self.nodes:
                    seed = cand
                    break

        if seed not in self.nodes:
            return {
                "seed": raw, "resolved": seed, "found": False, "depth": depth,
                "nodes": [], "edges": [], "mermaid": "",
                "note": "no node in the graph carries that address; it may be in "
                        "the logs without ever having been observed in a connection",
            }

        depth = max(0, min(int(depth), 6))       # keep a typo from walking the fleet
        hops = {seed: 0}
        frontier = {seed}
        for d in range(1, depth + 1):
            nxt = set()
            for e in self.edges.values():
                if e.source in frontier and e.target not in hops:
                    nxt.add(e.target)
                if e.target in frontier and e.source not in hops:
                    nxt.add(e.source)
            if not nxt:
                break
            for n in nxt:
                hops[n] = d
            frontier = nxt

        # Only ids that actually have a node. Edges can outlive their endpoints
        # (see prune_dangling_edges) and a traversal must not die on one.
        ids = {n for n in hops if n in self.nodes}
        edges = [e for e in self.edges.values() if e.source in ids and e.target in ids]

        nodes_out = []
        for nid in sorted(ids, key=lambda n: (hops[n], n)):
            d = self.nodes[nid].to_dict()
            d["hops"] = hops[nid]
            nodes_out.append(d)

        return {
            "seed": raw,
            "resolved": seed,
            "found": True,
            "depth": depth,
            "node_count": len(ids),
            "edge_count": len(edges),
            "nodes": nodes_out,
            "edges": [e.to_dict() for e in edges],
            "mermaid": self.to_mermaid(only=ids),
        }

    def to_mermaid(self, only: Optional[Set[str]] = None) -> str:
        """Generates dynamic renderable Mermaid flowchart with live edge volumes and status highlights.

        `only` restricts the drawing to a set of node ids -- used by subgraph()
        so a neighbourhood renders in the same visual language as the full map
        rather than in a second, divergent one.
        """
        lines = ["flowchart LR"]

        visible = [n for n in self.nodes.values() if only is None or n.id in only]

        # Subgraphs grouping. Every visible node MUST land in exactly one group:
        # a node that is styled or made clickable but never declared as a shape
        # is a hard mermaid parse error, and the whole diagram fails to draw.
        # That is what happened when the documented WireGuard peers were added to
        # the node table -- phone-full, chromebook-split, laptop and friends
        # are type "client", matched none of the three groups below, and had no
        # edges to auto-declare them, so `class phone_full healthy;` referred to
        # nothing and the dashboard went blank.
        workstations = [n for n in visible if n.type == "workstation"]
        core_services = [n for n in visible if n.type in ("server", "service")]
        gateways = [n for n in visible if n.type in ("gateway", "cloud", "external")]
        grouped = {n.id for n in workstations + core_services + gateways}
        others = [n for n in visible if n.id not in grouped]

        def _safe_id(nid: str) -> str:
            return nid.replace(":", "_").replace("-", "_").replace(".", "_")

        if workstations:
            lines.append("    subgraph Workstations [\"Workstations\"]")
            for w in workstations:
                lines.append(f"        {_safe_id(w.id)}[\"{w.name}\"]")
            lines.append("    end")

        if core_services:
            lines.append("    subgraph CoreFleet [\"Core Fleet & Services\"]")
            for c in core_services:
                lines.append(f"        {_safe_id(c.id)}[\"{c.name}\"]")
            lines.append("    end")

        if gateways:
            lines.append("    subgraph Perimeter [\"Gateways & Cloud\"]")
            for g in gateways:
                lines.append(f"        {_safe_id(g.id)}[\"{g.name}\"]")
            lines.append("    end")

        if others:
            lines.append("    subgraph Clients [\"Clients & Peers\"]")
            for o in others:
                lines.append(f"        {_safe_id(o.id)}[\"{o.name}\"]")
            lines.append("    end")

        # Everything that will be styled or made clickable below.
        declared = {n.id for n in workstations + core_services + gateways + others}

        lines.append("")
        # Edges and dynamic link styles
        link_styles = []
        drawn = [e for e in self.edges.values()
                 if only is None or (e.source in only and e.target in only)]
        for idx, e in enumerate(drawn):
            s_id = _safe_id(e.source)
            t_id = _safe_id(e.target)

            rate_str = format_rate_1m(e.rate_1m)
            bw_str = f" • {format_bytes_rate(e.bytes_per_sec)}" if e.bytes_per_sec > 0 else ""
            label = f"{e.protocol} ({rate_str}{bw_str})"
            stroke_w = e.get_stroke_width()

            if e.status == "SILENT":
                lines.append(f"    {s_id} -.->|\"SILENT ({e.protocol})\"| {t_id}")
                link_styles.append(f"    linkStyle {idx} stroke:#64748b,stroke-width:1px,stroke-dasharray: 4 4;")
            elif e.status == "SURGING":
                lines.append(f"    {s_id} -->|\"SURGE: {label}\"| {t_id}")
                link_styles.append(f"    linkStyle {idx} stroke:#ef4444,stroke-width:{max(stroke_w, 6)}px;")
            elif e.status == "NOVEL":
                lines.append(f"    {s_id} -->|\"NOVEL: {label}\"| {t_id}")
                link_styles.append(f"    linkStyle {idx} stroke:#f59e0b,stroke-width:{stroke_w}px;")
            elif e.status == "STARVED":
                lines.append(f"    {s_id} -->|\"STARVED: {label}\"| {t_id}")
                link_styles.append(f"    linkStyle {idx} stroke:#c084fc,stroke-width:1px,stroke-dasharray: 2 2;")
            else:
                lines.append(f"    {s_id} -->|\"{label}\"| {t_id}")
                color = "#38bdf8" if stroke_w <= 3 else ("#3b82f6" if stroke_w <= 6 else "#6366f1")
                link_styles.append(f"    linkStyle {idx} stroke:{color},stroke-width:{stroke_w}px;")

        lines.append("")
        lines.extend(link_styles)

        # Styles
        lines.append("")
        lines.append("    classDef default fill:#1a1d24,stroke:#374151,stroke-width:1px,color:#e5e7eb;")
        lines.append("    classDef healthy fill:#064e3b,stroke:#059669,stroke-width:2px,color:#a7f3d0;")
        lines.append("    classDef degraded fill:#7f1d1d,stroke:#dc2626,stroke-width:2px,color:#fecaca;")
        lines.append("    classDef novel fill:#78350f,stroke:#d97706,stroke-width:2px,color:#fde68a;")

        # Style and click ONLY nodes that were declared above. Referring to an
        # undeclared id here is fatal to the whole diagram, not just to that node.
        for n in self.nodes.values():
            if n.id not in declared:
                continue
            s_id = _safe_id(n.id)
            if n.status == "DEGRADED":
                lines.append(f"    class {s_id} degraded;")
            elif n.status == "HEALTHY":
                lines.append(f"    class {s_id} healthy;")

        # Node click handlers for interactive UI inspection
        lines.append("")
        for n in self.nodes.values():
            if n.id not in declared:
                continue
            s_id = _safe_id(n.id)
            lines.append(f'    click {s_id} onNodeClick "Inspect {n.name}"')

        return "\n".join(lines)

    def get_prometheus_metrics(self) -> List[str]:
        """Exports traffic graph metrics for Prometheus/Alloy scraper."""
        lines = []
        lines.append("# HELP lognode_graph_nodes_total Total fleet graph nodes")
        lines.append("# TYPE lognode_graph_nodes_total gauge")
        lines.append(f"lognode_graph_nodes_total {len(self.nodes)}")

        lines.append("# HELP lognode_graph_edges_total Total fleet graph edges")
        lines.append("# TYPE lognode_graph_edges_total gauge")
        lines.append(f"lognode_graph_edges_total {len(self.edges)}")

        lines.append("# HELP lognode_graph_shifts_active Active topological shifts detected")
        lines.append("# TYPE lognode_graph_shifts_active gauge")
        lines.append(f"lognode_graph_shifts_active {len(self.shifts)}")

        lines.append("# HELP lognode_graph_edge_rate_1m Instantaneous 1-minute edge traffic rate")
        lines.append("# TYPE lognode_graph_edge_rate_1m gauge")
        for e in self.edges.values():
            lines.append(
                f'lognode_graph_edge_rate_1m{{source="{e.source}",target="{e.target}",protocol="{e.protocol}",channel="{e.channel}",status="{e.status}"}} {e.rate_1m}'
            )

        lines.append("# HELP lognode_graph_edge_bytes_per_sec Instantaneous edge bandwidth in bytes/sec")
        lines.append("# TYPE lognode_graph_edge_bytes_per_sec gauge")
        for e in self.edges.values():
            lines.append(
                f'lognode_graph_edge_bytes_per_sec{{source="{e.source}",target="{e.target}",protocol="{e.protocol}",channel="{e.channel}"}} {e.bytes_per_sec}'
            )

        lines.append("# HELP lognode_graph_edge_stroke_width Dynamic Mermaid line stroke width")
        lines.append("# TYPE lognode_graph_edge_stroke_width gauge")
        for e in self.edges.values():
            lines.append(
                f'lognode_graph_edge_stroke_width{{source="{e.source}",target="{e.target}",protocol="{e.protocol}",channel="{e.channel}"}} {e.get_stroke_width()}'
            )

        return lines
