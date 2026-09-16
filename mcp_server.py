#!/usr/bin/env python3
"""
LogNode MCP Server
==================
Exposes LogNode's millisecond-speed log query engine, telemetry stats,
template synthesis, and durability triggers to AI assistants (Antigravity, Claude, etc.)
via the Model Context Protocol (MCP) over Stdio.

Works with both the official MCP SDK (`mcp.server.MCPServer`) and includes
a zero-dependency pure Python JSON-RPC stdio fallback for instant startup with `python3`.
"""

import os
import sys
import time
import json
import urllib.error
import urllib.request
import urllib.parse
from typing import Optional, Dict, Any, List

LOGNODE_URL = os.environ.get("LOGNODE_URL", "http://127.0.0.1:9514").rstrip("/")

def _http_get(endpoint: str, params: Optional[Dict[str, Any]] = None, timeout: int = 10) -> Dict[str, Any]:
    url = f"{LOGNODE_URL}{endpoint}"
    if params:
        filtered_params = {k: v for k, v in params.items() if v is not None}
        if filtered_params:
            url += "?" + urllib.parse.urlencode(filtered_params)
    
    req = urllib.request.Request(url, headers={"User-Agent": "LogNode-MCP/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # A 4xx carries the server's explanation of what was wrong with the
        # call. Raising here hands the agent a stack trace instead of the
        # sentence that tells it how to fix the request.
        try:
            return json.loads(exc.read().decode("utf-8"))
        except Exception:
            return {"error": "HTTP %s: %s" % (exc.code, exc.reason)}
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}

def _http_post(endpoint: str, data: Dict[str, Any], timeout: int = 15) -> Dict[str, Any]:
    url = f"{LOGNODE_URL}{endpoint}"
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "LogNode-MCP/1.0"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # A 4xx carries the server's explanation of what was wrong with the
        # call. Raising here hands the agent a stack trace instead of the
        # sentence that tells it how to fix the request.
        try:
            return json.loads(exc.read().decode("utf-8"))
        except Exception:
            return {"error": "HTTP %s: %s" % (exc.code, exc.reason)}
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


# =====================================================================
# Tool Implementations
# =====================================================================

def query_logs(
    q: Optional[str] = None,
    instance: Optional[str] = None,
    event: Optional[str] = None,
    source: Optional[str] = None,
    since: Optional[str] = "1h",
    limit: int = 50
) -> str:
    """
    Query high-speed structured fleet logs from LogNode with millisecond index-backed search.

    Args:
        q: Substring or free-text to search in raw log messages (accelerated by trigram index).
        instance: Filter by fleet host/instance name (e.g. 'laptop', 'laptop', 'hub', 'app-server', 'app-server').
        event: Filter by synthesized event template name (e.g. 'auth_success', 'service_failure', 'df_session_check').
        source: Filter by log source/collector (e.g. 'journald', 'macos-system', 'ollama').
        since: Relative time duration backwards (e.g. '5m', '15m', '1h', '24h', '7d'). Default is '1h'.
        limit: Maximum number of log records to return (default 50, max 1000).
    """
    try:
        data = _http_get("/query", {
            "q": q,
            "instance": instance,
            "event": event,
            "source": source,
            "since": since,
            "limit": limit
        })

        count = data.get("count", 0)
        query_time = data.get("query_time_ms", 0.0)
        events = data.get("events", [])

        if not events:
            filters_desc = ", ".join(f"{k}={v}" for k, v in data.get("filters", {}).items() if v)
            return f"LogNode: 0 events found ({query_time} ms). Filters: [{filters_desc}]"

        lines = [
            f"=== LogNode Query Results: {count} events ({query_time} ms) ===",
            f"Filters: instance={instance or '*'}, q={q or '*'}, event={event or '*'}, source={source or '*'}, since={since or 'all'}",
            "-" * 70
        ]

        for ev in events:
            ts = ev.get("timestamp", "")
            host = ev.get("labels", {}).get("instance", "unknown")
            ev_name = ev.get("event", "unstructured")
            src = ev.get("labels", {}).get("source", "")
            raw = ev.get("raw", "")
            kv = ev.get("kv", {})

            header = f"[{ts}] [{host}] [{ev_name}]"
            if src:
                header += f" (source: {src})"
            lines.append(header)
            lines.append(f"  Raw: {raw}")
            if kv:
                lines.append(f"  KV: {json.dumps(kv, ensure_ascii=False)}")
            lines.append("")

        return "\n".join(lines)
    except Exception as e:
        return f"LogNode query error: {e}"


def get_fleet_stats() -> str:
    """
    Retrieve real-time LogNode ingestion stats, hot-path regex hit rates, queue depths,
    memory clusterer bucket counts, and system health across the fleet.
    """
    try:
        data = _http_get("/stats")
        stats = data.get("stats", {})
        total = stats.get("total_ingested", 0)
        hot = stats.get("hot_path_matches", 0)
        cold = stats.get("cold_path_buffered", 0)
        synthesized = stats.get("templates_synthesized", 0)
        hit_rate = round((hot / total * 100), 2) if total > 0 else 0.0

        res = [
            "=== LogNode Fleet Telemetry & Health ===",
            f"Status: {data.get('status', 'unknown')}",
            f"Uptime: {data.get('uptime_s', 0)} seconds",
            f"Postgres Connected: {data.get('postgres_connected', False)}",
            f"Postgres Queue Depth: {data.get('pg_queue_size', 0)} / 50000",
            f"Clusterer Active Buckets: {data.get('clusterer_buckets', 0)} / 2000",
            f"Active Learned Templates: {data.get('templates_loaded', 0)}",
            "",
            "Ingestion Breakdown:",
            f"  - Total Logs Ingested: {total:,}",
            f"  - Hot-Path Regex Matches: {hot:,} ({hit_rate}% hit rate)",
            f"  - Cold-Path Buffered: {cold:,}",
            f"  - LLM Synthesized Templates: {synthesized}"
        ]
        return "\n".join(res)
    except Exception as e:
        return f"LogNode stats error: {e}"


def list_templates(limit: int = 30, order_by: str = "hits") -> str:
    """
    List synthesized regex event templates learned by the LogNode SLM/regex pipeline,
    including hit counts, extracted variable fields, and regex patterns.

    Args:
        limit: Maximum number of templates to display (default 30).
        order_by: 'hits' (most frequent first) or 'recent' (newest first). Default is 'hits'.
    """
    try:
        rules = _http_get("/templates")
        if order_by == "recent":
            rules.sort(key=lambda r: r.get("created_at", 0), reverse=True)
        else:
            rules.sort(key=lambda r: r.get("hit_count", 0), reverse=True)

        selected = rules[:min(limit, 200)]
        lines = [
            f"=== LogNode Synthesized Templates (Showing {len(selected)} of {len(rules)}, sorted by {order_by}) ===",
            "-" * 75
        ]

        for r in selected:
            ev = r.get("event", "unknown")
            hits = r.get("hit_count", 0)
            fields = ", ".join(r.get("fields", [])) or "(none)"
            pattern = r.get("pattern", "")
            if len(pattern) > 100:
                pattern = pattern[:97] + "..."
            lines.append(f"• Event: {ev} | Hits: {hits:,} | Fields: [{fields}]")
            lines.append(f"  Pattern: {pattern}")
            lines.append("")

        return "\n".join(lines)
    except Exception as e:
        return f"LogNode list_templates error: {e}"


def sync_storage() -> str:
    """
    Trigger an immediate PostgreSQL CHECKPOINT and persistent rsync snapshot
    from RAM tmpfs (/dev/shm) to NVMe persistent storage on the LogNode host.
    """
    try:
        data = _http_post("/sync", {})
        status = data.get("status", "unknown")
        sync_ms = data.get("sync_time_ms", 0.0)
        target = data.get("target", "")
        return (
            f"LogNode Storage Snapshot Complete:\n"
            f"Status: {status}\n"
            f"Sync Latency: {sync_ms} ms\n"
            f"Persistent Target: {target}"
        )
    except Exception as e:
        return f"LogNode sync error: {e}"


def ingest_log(line: str, instance: Optional[str] = "agent", source: Optional[str] = "mcp") -> str:
    """
    Ingest an ad-hoc or synthetic log entry into LogNode for instant clustering, pattern learning, and storage.

    Args:
        line: The raw log message to ingest.
        instance: Originating host or instance label (default: 'agent').
        source: Log source or collector label (default: 'mcp').
    """
    try:
        payload = {
            "line": line,
            "labels": {
                "instance": instance or "agent",
                "source": source or "mcp"
            }
        }
        data = _http_post("/ingest", payload)
        processed = data.get("processed", 0)
        results = data.get("results", [])
        res_info = results[0] if results else {}
        return (
            f"LogNode Ingestion Success: processed {processed} item(s).\n"
            f"Event Name: {res_info.get('event', 'unknown')}\n"
            f"Matched By: {res_info.get('matched_by', 'unknown')}\n"
            f"Latency: {res_info.get('latency_us', 0)} µs"
        )
    except Exception as e:
        return f"LogNode ingest error: {e}"


def get_anomalies() -> str:
    """
    Retrieve currently active statistical rate spikes, unstructured log surges,
    or critical hardware/kernel anomalies detected across the fleet.
    """
    try:
        data = _http_get("/anomalies")
        calib = data.get("calibration", {})
        anomalies = data.get("anomalies", [])
        state = calib.get("state", "UNKNOWN")
        remaining = calib.get("seconds_remaining", 0)

        header = f"=== LogNode Fleet Anomaly Status [State: {state}"
        if state == "CALIBRATING":
            header += f" ({remaining}s remaining)] ==="
        else:
            header += "] ==="

        if not anomalies:
            return f"{header}\nAll systems nominal. 0 active anomalies detected."

        lines = [
            header,
            f"Detected Anomalies: {len(anomalies)} active",
            "-" * 70
        ]
        for a in anomalies:
            inst = a.get("instance", "unknown")
            ev = a.get("event", "unknown")
            a_type = a.get("type", "anomaly")
            ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(a.get("timestamp", 0)))

            if a_type == "rate_spike":
                lines.append(f"• [RATE SPIKE] Host: `{inst}` | Event: `{ev}` | Time: {ts}")
                lines.append(f"  Rate: {a.get('count_1m')}/min vs {a.get('avg_1m')}/min baseline (+{a.get('z_score')}σ)")
            elif a_type == "unstructured_surge":
                lines.append(f"• [UNSTRUCTURED SURGE] Host: `{inst}` | Time: {ts}")
                lines.append(f"  Ratio: {a.get('ratio')}% unrecognized logs ({a.get('count_1m')}/{a.get('total_1m')} in last minute)")
            else:
                lines.append(f"• [{a_type.upper()}] Host: `{inst}` | Event: `{ev}` | Details: {json.dumps(a)}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return f"LogNode get_anomalies error: {e}"


def test_discord_alert() -> str:
    """
    Dispatch a test alert to Discord to verify the alert-of-last-resort pipeline and webhook connectivity.
    """
    try:
        data = _http_post("/alert/test", {
            "title": "LogNode MCP Verification Probe",
            "description": "Manual alert test triggered via AI Agent Model Context Protocol (MCP).",
            "severity": "info",
            "instance": "mcp-agent",
            "event": "mcp_probe",
            "spike_info": "Nominal Baseline Probe"
        })
        return f"LogNode Discord Alert Test Result: {json.dumps(data, indent=2)}"
    except Exception as e:
        return f"LogNode test_discord_alert error: {e}"


def get_traffic_graph(format: Optional[str] = "json") -> str:
    """
    Retrieve the current connected traffic graph representing all fleet nodes,
    directed communication edges, and instantaneous flow rates.

    Args:
        format: Output format ('json' for full topology entities or 'mermaid' for visual diagram).
    """
    try:
        fmt = (format or "json").lower()
        if fmt == "mermaid":
            url = f"{LOGNODE_URL}/graph/mermaid?format=text"
            req = urllib.request.Request(url, headers={"User-Agent": "LogNode-MCP/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                chart = resp.read().decode("utf-8")
            return f"```mermaid\n{chart}\n```"

        data = _http_get("/graph")
        summary = data.get("summary", {})
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        shifts = data.get("shifts", [])

        lines = [
            "=== LogNode Fleet Traffic Graph ===",
            f"Fleet Status: {summary.get('fleet_status', 'UNKNOWN')} | Nodes: {summary.get('total_nodes', 0)} | Edges: {summary.get('total_edges', 0)} | Shifts: {summary.get('active_shifts', 0)}",
            "-" * 70,
            "Nodes:"
        ]
        for n in nodes:
            lines.append(f"  • {n.get('id')} [{n.get('type')}]: {n.get('role')} (Status: {n.get('status')})")

        lines.append("\nActive Edges & Flow Rates:")
        for e in sorted(edges, key=lambda x: x.get("rate_1m", 0), reverse=True):
            status_icon = "🟢" if e.get("status") == "HEALTHY" else ("🔴" if e.get("status") == "SILENT" else "🟡")
            lines.append(
                f"  {status_icon} {e.get('source')} -> {e.get('target')} [{e.get('protocol')}:{e.get('channel')}]"
                f" | 1m Rate: {e.get('rate_1m', 0):.0f} logs/min | 15m Baseline: {e.get('baseline_15m', 0):.1f}/min | Status: {e.get('status')}"
            )

        if shifts:
            lines.append("\n⚠️ Active Topology Shifts:")
            for s in shifts:
                lines.append(f"  [{s.get('severity', '').upper()}] {s.get('type')}: {s.get('message')}")
        else:
            lines.append("\nTopology Shifts: None detected (nominal topology).")

        return "\n".join(lines)
    except Exception as e:
        return f"LogNode get_traffic_graph error: {e}"


def get_traffic_shifts() -> str:
    """
    Retrieve active topology shifts across fleet communication flows (broken/silent links,
    flow surges > 4σ, unmapped novel edges, or starved pipelines).
    """
    try:
        data = _http_get("/graph/shifts")
        count = data.get("count", 0)
        shifts = data.get("shifts", [])

        if not shifts:
            return "LogNode Topology Health: No active topology shifts. All fleet communication channels are nominal."

        lines = [
            f"=== LogNode Active Topology Shifts ({count} detected) ===",
            "-" * 70
        ]
        for s in shifts:
            sev = s.get("severity", "info").upper()
            stype = s.get("type", "UNKNOWN")
            src = s.get("source", "unknown")
            tgt = s.get("target", "unknown")
            msg = s.get("message", "")
            r1m = s.get("rate_1m", 0.0)
            b15m = s.get("baseline_15m", 0.0)

            icon = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "WARNING" else "🟡")
            lines.append(f"{icon} [{sev}] {stype}: {src} -> {tgt}")
            lines.append(f"   Details: {msg}")
            lines.append(f"   Metrics: 1m={r1m:.1f}/min | 15m baseline={b15m:.1f}/min")
            lines.append("")

        return "\n".join(lines)
    except Exception as e:
        return f"LogNode get_traffic_shifts error: {e}"


def get_subgraph(
    ip: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    instance: Optional[str] = None,
    process: Optional[str] = None,
    since: Optional[str] = "1h",
    depth: int = 1,
    format: Optional[str] = "json"
) -> str:
    """
    Search and extract an incident subgraph by IP/CIDR, port, protocol, host instance,
    or process name across current topology and historical network telemetry.

    Args:
        ip: Target IP or CIDR to isolate (e.g. '127.0.0.1', '192.0.2.10/24').
        port: Target TCP/UDP port number (e.g. 443, 22, 53, 9514).
        protocol: Network protocol (e.g. 'tcp', 'udp', 'dns', 'ssh').
        instance: Host/instance name (e.g. 'hub', 'laptop', 'vault-host').
        process: Process name or command (e.g. 'sshd', 'nginx', 'python3').
        since: Historical time window (e.g. '5m', '15m', '1h', '6h', '24h'). Default '1h'.
        depth: BFS hop traversal depth from matched nodes (default 1).
        format: Output format ('json' for structured breakdown, 'mermaid' for visual diagram).
    """
    try:
        params = {
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "instance": instance,
            "process": process,
            "since": since,
            "depth": depth
        }
        fmt = (format or "json").lower()
        if fmt == "mermaid":
            params["format"] = "mermaid"
            filtered = {k: v for k, v in params.items() if v is not None}
            url = f"{LOGNODE_URL}/graph/subgraph?" + urllib.parse.urlencode(filtered)
            req = urllib.request.Request(url, headers={"User-Agent": "LogNode-MCP/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                chart = resp.read().decode("utf-8")
            return f"```mermaid\n{chart}\n```"

        params["format"] = "json"
        data = _http_get("/graph/subgraph", params)
        if data.get("error"):
            return f"Subgraph query error: {data['error']}"

        summary = data.get("summary", {})
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        matched_flows = summary.get("matched_flows", len(edges))
        corr_events = data.get("correlated_events", [])

        lines = [
            "=== LogNode Incident Subgraph ===",
            f"Nodes: {len(nodes)} | Edges: {len(edges)} | Matched Flows: {matched_flows} | Correlated Events: {len(corr_events)}",
            f"Filters: ip={ip or '*'}, port={port or '*'}, proto={protocol or '*'}, host={instance or '*'}, proc={process or '*'}, since={since or '1h'}",
            "-" * 70,
            "Nodes:"
        ]
        for n in nodes:
            lines.append(f"  • {n.get('id')} [{n.get('type')}]: {n.get('role')} (Status: {n.get('status')})")

        lines.append("\nFlow Edges:")
        for e in sorted(edges, key=lambda x: x.get("rate_1m", 0), reverse=True):
            status_icon = "🟢" if e.get("status") == "HEALTHY" else ("🔴" if e.get("status") == "SILENT" else "🟡")
            lines.append(
                f"  {status_icon} {e.get('source')} -> {e.get('target')} [{e.get('protocol')}:{e.get('channel')}]"
                f" | 1m Rate: {e.get('rate_1m', 0):.0f}/min | 15m: {e.get('baseline_15m', 0):.1f}/min | Status: {e.get('status')}"
            )

        if corr_events:
            lines.append(f"\nCorrelated Network Telemetry Events (showing up to 10 of {len(corr_events)}):")
            for ev in corr_events[:10]:
                ts = ev.get("timestamp", "")
                host_label = ev.get("labels", {}).get("instance", "")
                raw = ev.get("raw", "")
                lines.append(f"  [{ts}] [{host_label}] {raw}")

        return "\n".join(lines)
    except Exception as e:
        return f"LogNode get_subgraph error: {e}"


def get_host_flows(
    host: str,
    since: Optional[str] = "1h",
    format: Optional[str] = "json"
) -> str:
    """
    Retrieve directed 3-tier process-level data flow graph for a single host
    (Inbound Clients -> Host Sockets/Processes -> Outbound Cloud/Peer Destinations).

    Args:
        host: Target host name (e.g. 'hub', 'laptop', 'vault-host', 'laptop').
        since: Historical time window (e.g. '5m', '15m', '1h', '6h', '24h'). Default '1h'.
        format: Output format ('json' for structured breakdown, 'mermaid' for visual flowchart).
    """
    try:
        fmt = (format or "json").lower()
        params = {"host": host, "since": since}
        if fmt == "mermaid":
            params["format"] = "mermaid"
            filtered = {k: v for k, v in params.items() if v is not None}
            url = f"{LOGNODE_URL}/graph/host-flows?" + urllib.parse.urlencode(filtered)
            req = urllib.request.Request(url, headers={"User-Agent": "LogNode-MCP/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                chart = resp.read().decode("utf-8")
            return f"```mermaid\n{chart}\n```"

        data = _http_get("/graph/host-flows", params)
        if data.get("error"):
            return f"Host flows error: {data['error']}"

        summary = data.get("summary", {})
        inbound = data.get("inbound", [])
        outbound = data.get("outbound", [])

        lines = [
            f"=== LogNode Data Flows for Host: {data.get('host', host)} ===",
            f"Time Window: {since} | Inbound Clients: {len(inbound)} | Outbound Destinations: {len(outbound)}",
            "-" * 70,
            "Inbound Traffic (Clients -> Host):"
        ]
        if inbound:
            for f in sorted(inbound, key=lambda x: x.get("rate_1m", 0), reverse=True):
                lines.append(f"  ⬇️ {f.get('source')} -> port {f.get('port')} [{f.get('protocol')}] ({f.get('process') or 'unknown'}) | 1m Rate: {f.get('rate_1m', 0):.1f}/min")
        else:
            lines.append("  (No inbound traffic detected in time window)")

        lines.append("\nOutbound Traffic (Host -> External/Peers):")
        if outbound:
            for f in sorted(outbound, key=lambda x: x.get("rate_1m", 0), reverse=True):
                lines.append(f"  ⬆️ {f.get('process') or 'process'} -> {f.get('target')}:{f.get('port')} [{f.get('protocol')}] | 1m Rate: {f.get('rate_1m', 0):.1f}/min")
        else:
            lines.append("  (No outbound traffic detected in time window)")

        return "\n".join(lines)
    except Exception as e:
        return f"LogNode get_host_flows error: {e}"


def get_time_lapse(
    host: Optional[str] = None,
    ip: Optional[str] = None,
    port: Optional[int] = None,
    since: Optional[str] = "1h",
    slices: int = 12
) -> str:
    """
    Retrieve discrete temporal time-lapse slices with connection delta detection
    (identifying newly formed, persisting, or terminated communication edges).

    Args:
        host: Host name to scope time-lapse playback.
        ip: Target IP address to isolate.
        port: Target port number.
        since: Total playback time window (e.g. '15m', '1h', '6h', '24h'). Default '1h'.
        slices: Number of discrete time slices (default 12, max 60).
    """
    try:
        params = {
            "host": host,
            "ip": ip,
            "port": port,
            "since": since,
            "slices": slices
        }
        data = _http_get("/graph/time-lapse", params)
        if data.get("error"):
            return f"Time-lapse error: {data['error']}"

        time_slices = data.get("slices", [])
        lines = [
            f"=== LogNode Temporal Time-Lapse Playback ===",
            f"Target: host={host or '*'}, ip={ip or '*'}, port={port or '*'} | Window: {since} ({len(time_slices)} slices of {data.get('slice_duration_s', 0):.0f}s)",
            "-" * 70
        ]
        for s in time_slices:
            idx = s.get("index", 0) + 1
            ts = time.strftime("%H:%M:%S", time.gmtime(s.get("timestamp", 0)))
            total_edges = s.get("total_edges", 0)
            new_edges = s.get("new_edges", 0)
            new_desc = f" | ⚡ +{new_edges} NEW edges: {', '.join(s.get('new_edge_keys', []))}" if new_edges > 0 else ""
            lines.append(f"Slice #{idx:02d} [{ts}] | Active Edges: {total_edges} | Rate: {s.get('total_rate', 0):.1f}/min{new_desc}")

        return "\n".join(lines)
    except Exception as e:
        return f"LogNode get_time_lapse error: {e}"


def query_graphql(query: str, variables: Optional[Dict[str, Any]] = None) -> str:
    """
    Execute an arbitrary GraphQL query against LogNode's /graphql endpoint.

    Args:
        query: GraphQL query or mutation string.
        variables: Optional variables dictionary.
    """
    try:
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        data = _http_post("/graphql", payload)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"LogNode GraphQL error: {e}"



# =====================================================================
# Standalone Pure-Python JSON-RPC stdio Engine (Zero external deps)
# =====================================================================


def list_findings(state: Optional[str] = "new", kind: Optional[str] = None,
                  limit: int = 25) -> str:
    """
    List detections awaiting triage. Start here.

    A finding is a detection that needs somebody to decide something -- a threat
    actor, a failed unit, a topology shift. `state` is one of new, triaging,
    triaged, dismissed, actioned; the default shows what has not been judged yet.

    Dismissing a finding makes it stay dismissed: the same subject recurring
    bumps its occurrence count instead of returning to the queue. That is the
    point of triaging rather than alerting.
    """
    params = {"limit": limit}
    if state:
        params["state"] = state
    if kind:
        params["kind"] = kind
    data = _http_get("/findings", params)
    rows = data.get("findings", [])
    if not rows:
        return "No findings matching that filter. Nothing is waiting on you."
    out = ["%d finding(s):" % len(rows), ""]
    for r in rows:
        out.append("  #%s  [%s] %s  subject=%s  seen=%sx  host=%s"
                   % (r["id"], r.get("state"), r.get("kind"), r.get("subject"),
                      r.get("occurrences"), r.get("instance") or "-"))
        if r.get("verdict"):
            out.append("       verdict=%s severity=%s by %s"
                       % (r["verdict"], r.get("severity"), r.get("reviewer")))
        if r.get("recommended_action"):
            out.append("       recommended: %s" % r["recommended_action"])
    out += ["", "Use get_finding(id) for the evidence before judging."]
    return "\n".join(out)


def get_finding(finding_id: int) -> str:
    """
    One finding with its full evidence: what was detected, how often, against
    which host, and everything the detector knew at the time.

    Investigate before judging. query_logs(q=<subject>) shows every line the
    subject appears in; get_traffic_graph and the /graph/subgraph endpoint show
    what it is connected to. A verdict without that context is a guess.
    """
    data = _http_get("/findings/%d" % int(finding_id))
    if data.get("error"):
        return "Error: %s" % data["error"]
    import json as _j
    ev = data.get("evidence") or {}
    lines = [
        "Finding #%s  [%s]" % (data.get("id"), data.get("state")),
        "  kind:        %s" % data.get("kind"),
        "  subject:     %s" % data.get("subject"),
        "  host:        %s" % (data.get("instance") or "-"),
        "  seen:        %s time(s), first %s, last %s"
        % (data.get("occurrences"), data.get("first_seen"), data.get("last_seen")),
        "  detector severity hint: %s" % data.get("severity_hint"),
        "",
        "Evidence:",
        _j.dumps(ev, indent=2, default=str)[:4000],
    ]
    if data.get("verdict"):
        lines += ["", "Already judged: %s (%s) by %s"
                  % (data["verdict"], data.get("severity"), data.get("reviewer")),
                  "  rationale: %s" % data.get("rationale")]
    return "\n".join(lines)


def submit_verdict(finding_id: int, verdict: str, rationale: str,
                   reviewer: str = "claude", severity: Optional[str] = None,
                   recommended_action: Optional[str] = None) -> str:
    """
    Record a judgement on a finding. This NEVER carries the action out.

    verdict: one of
      real          - genuine, and someone should look
      needs-action  - genuine and something should change
      known         - understood and accepted (a scanner that always does this)
      noise         - not worth a human's attention
      false-positive - the detector was wrong

    `rationale` is required and must say WHY -- it is what a human reads when
    they disagree with the verdict later, and a judgement nobody can audit is
    worse than none.

    `recommended_action` is free text for a human to act on. Nothing in LogNode
    executes it. If a finding warrants blocking an address or changing a rule,
    say so here and leave the doing to a person.
    """
    body = {"verdict": verdict, "rationale": rationale, "reviewer": reviewer}
    if severity:
        body["severity"] = severity
    if recommended_action:
        body["recommended_action"] = recommended_action
    data = _http_post("/findings/%d/verdict" % int(finding_id), body)
    if data.get("error"):
        return "Rejected: %s" % data["error"]
    f = data.get("finding", {})
    return ("Recorded on finding #%s: verdict=%s state=%s severity=%s%s"
            % (f.get("id"), f.get("verdict"), f.get("state"), f.get("severity"),
               ("\n  recommended (NOT executed): " + f["recommended_action"])
               if f.get("recommended_action") else ""))


def triage_summary() -> str:
    """How much is waiting, and how long the oldest has waited."""
    d = _http_get("/findings/summary")
    if d.get("error"):
        return "Error: %s" % d["error"]
    by = d.get("by_state") or {}
    return ("Awaiting triage: %s\n  by state: %s\n  oldest untriaged: %s"
            % (d.get("awaiting_triage", 0),
               ", ".join("%s=%s" % kv for kv in sorted(by.items())) or "none",
               d.get("oldest_untriaged") or "-"))


def list_campaign_actors(limit: int = 50) -> str:
    """
    List attributed campaign actors with their generated codenames, TTP profiles, and follow-up tags.
    Useful for tracking adversary campaigns across rotating IP addresses and observing long-term trends.
    """
    data = _http_get("/threats/campaigns", {"limit": limit})
    rows = data.get("campaign_actors", [])
    if not rows:
        return "No campaign actors currently tagged in persistent registry."
    out = ["%d campaign actor(s):" % len(rows), ""]
    for r in rows:
        tags_str = ", ".join(r.get("followup_tags", [])) or "no follow-up tags"
        emoji_prefix = f"{r.get('emoji')} " if r.get('emoji') else ""
        out.append(f"  [{r.get('actor_id')}] {emoji_prefix}{r.get('codename')} (Tier: {r.get('threat_tier')})")
        out.append(f"       TTPs: {r.get('fingerprint')}")
        out.append(f"       Follow-up tags: {tags_str}")
        if r.get("notes"):
            out.append(f"       Notes: {r.get('notes')}")
        if r.get("first_seen"):
            out.append(f"       First Seen: {r.get('first_seen')}")
        if r.get("last_seen"):
            out.append(f"       Last Seen: {r.get('last_seen')}")
        out.append("")
    return "\n".join(out)


def tag_campaign_actor(actor_id: str, followup_tags: List[str], notes: str = "",
                       codename: Optional[str] = None, emoji: Optional[str] = None,
                       fingerprint: Optional[str] = None) -> str:
    """
    Tag an attributed campaign actor with follow-up directives (e.g. ['firewall-block', 'monitor-ssh'])
    and investigation notes for long-term tracking.
    """
    body = {
        "followup_tags": followup_tags,
        "notes": notes,
        "codename": codename,
        "emoji": emoji,
        "fingerprint": fingerprint
    }
    data = _http_post(f"/threats/campaign/{actor_id}/tag", body)
    if data.get("error"):
        return f"Error: {data['error']}"
    r = data.get("campaign_actor", {})
    return f"Tagged actor {r.get('actor_id')} ({r.get('codename')}) with tags: {r.get('followup_tags')}"


TOOL_REGISTRY = {
    "list_findings": {
        "fn": list_findings,
        "description": "List detections awaiting triage. Start here when reviewing what LogNode has found.",
        "parameters": {
            "type": "object",
            "properties": {
                "state": {"type": "string", "description": "new | triaging | triaged | dismissed | actioned. Default 'new'."},
                "kind": {"type": "string", "description": "Filter by detector: threat_actor, unit_failed, topology_shift."},
                "limit": {"type": "integer", "description": "Max findings to return (default 25)."}
            }
        }
    },
    "get_finding": {
        "fn": get_finding,
        "description": "Full evidence for one finding. Read this, and investigate with query_logs, before judging.",
        "parameters": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer", "description": "The finding id from list_findings."}
            },
            "required": ["finding_id"]
        }
    },
    "submit_verdict": {
        "fn": submit_verdict,
        "description": "Record a judgement on a finding. Recommended actions are recorded for a human, never executed.",
        "parameters": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer", "description": "The finding id."},
                "verdict": {"type": "string", "description": "real | needs-action | known | noise | false-positive"},
                "rationale": {"type": "string", "description": "Required. Why you judged it this way -- a human reads this when they disagree."},
                "reviewer": {"type": "string", "description": "Who is judging (default 'claude')."},
                "severity": {"type": "string", "description": "info | low | medium | high | critical"},
                "recommended_action": {"type": "string", "description": "What a human should consider doing. Not executed."}
            },
            "required": ["finding_id", "verdict", "rationale"]
        }
    },
    "triage_summary": {
        "fn": triage_summary,
        "description": "How many findings await triage, and how long the oldest has waited.",
        "parameters": {"type": "object", "properties": {}}
    },

    "query_logs": {
        "fn": query_logs,
        "description": "Query high-speed structured fleet logs from LogNode with millisecond index-backed search.",
        "parameters": {
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "Free text or substring to search for in log raw text (accelerated by pg_trgm trigram index)."},
                "instance": {"type": "string", "description": "Filter by fleet host name (e.g. 'laptop', 'laptop', 'hub', 'app-server', 'app-server')."},
                "event": {"type": "string", "description": "Filter by synthesized event template name (e.g. 'auth_success', 'service_failure')."},
                "source": {"type": "string", "description": "Filter by log source (e.g. 'journald', 'macos-system', 'ollama')."},
                "since": {"type": "string", "description": "Time window to search (e.g. '5m', '15m', '1h', '24h', '7d'). Default is '1h'."},
                "limit": {"type": "integer", "description": "Maximum number of log events to return (default 50, max 1000)."}
            }
        }
    },
    "get_fleet_stats": {
        "fn": get_fleet_stats,
        "description": "Retrieve real-time LogNode ingestion stats, hot-path regex hit rates, queue depths, and health across the fleet.",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },
    "list_templates": {
        "fn": list_templates,
        "description": "List synthesized regex event templates, extraction fields, and hit counts.",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Maximum number of templates to return (default 30)."},
                "order_by": {"type": "string", "description": "'hits' (most frequent first) or 'recent' (newest first). Default 'hits'."}
            }
        }
    },
    "sync_storage": {
        "fn": sync_storage,
        "description": "Trigger an immediate PostgreSQL CHECKPOINT and persistent snapshot from RAM tmpfs to NVMe storage.",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },
    "ingest_log": {
        "fn": ingest_log,
        "description": "Send an ad-hoc or synthetic log message into LogNode for clustering and storage.",
        "parameters": {
            "type": "object",
            "properties": {
                "line": {"type": "string", "description": "The raw log message to ingest."},
                "instance": {"type": "string", "description": "Originating host name (default 'agent')."},
                "source": {"type": "string", "description": "Log source label (default 'mcp')."}
            },
            "required": ["line"]
        }
    },
    "get_anomalies": {
        "fn": get_anomalies,
        "description": "Retrieve currently active statistical rate spikes, unstructured surges, or critical alerts.",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },
    "get_traffic_graph": {
        "fn": get_traffic_graph,
        "description": "Retrieve the connected fleet domain traffic graph (nodes, directed flows, and rates) as structured text or Mermaid diagram.",
        "parameters": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["json", "mermaid"],
                    "description": "Output format: 'json' for node/edge breakdown, 'mermaid' for visual flowchart diagram."
                }
            }
        }
    },
    "get_traffic_shifts": {
        "fn": get_traffic_shifts,
        "description": "Retrieve active topology shifts across the fleet (broken/silent links, volume surges, novel edges, flow starvation).",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },
    "test_discord_alert": {
        "fn": test_discord_alert,
        "description": "Dispatch a test alert to Discord to verify webhook connectivity.",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },
    "get_subgraph": {
        "fn": get_subgraph,
        "description": "Search and extract an incident subgraph by IP/CIDR, port, protocol, host, or process across topology and network events.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Target IP address or CIDR to isolate."},
                "port": {"type": "integer", "description": "Target TCP/UDP port number."},
                "protocol": {"type": "string", "description": "Network protocol (e.g. tcp, udp, dns, ssh)."},
                "instance": {"type": "string", "description": "Host/instance name (e.g. hub, laptop, vault-host)."},
                "process": {"type": "string", "description": "Process name (e.g. sshd, nginx, python3)."},
                "since": {"type": "string", "description": "Time window (e.g. '5m', '15m', '1h', '24h'). Default '1h'."},
                "depth": {"type": "integer", "description": "BFS hop traversal depth (default 1)."},
                "format": {"type": "string", "enum": ["json", "mermaid"], "description": "Output format: 'json' or 'mermaid'."}
            }
        }
    },
    "get_host_flows": {
        "fn": get_host_flows,
        "description": "Retrieve directed 3-tier process-level data flows for a single host (inbound -> sockets -> outbound).",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Host name (e.g. hub, laptop, vault-host)."},
                "since": {"type": "string", "description": "Time window (e.g. '5m', '15m', '1h', '24h'). Default '1h'."},
                "format": {"type": "string", "enum": ["json", "mermaid"], "description": "Output format: 'json' or 'mermaid'."}
            },
            "required": ["host"]
        }
    },
    "get_time_lapse": {
        "fn": get_time_lapse,
        "description": "Retrieve discrete temporal time-lapse slices with connection delta detection.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Host name to scope time-lapse."},
                "ip": {"type": "string", "description": "Target IP address."},
                "port": {"type": "integer", "description": "Target port number."},
                "since": {"type": "string", "description": "Time window (e.g. '15m', '1h', '24h'). Default '1h'."},
                "slices": {"type": "integer", "description": "Number of time slices (default 12)."}
            }
        }
    },
    "query_graphql": {
        "fn": query_graphql,
        "description": "Execute an arbitrary GraphQL query or mutation against LogNode's /graphql endpoint.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The GraphQL query string."},
                "variables": {"type": "object", "description": "Optional variables dictionary."}
            },
            "required": ["query"]
        }
    },
    "list_campaign_actors": {
        "fn": list_campaign_actors,
        "description": "List attributed adversary campaign actors with their generated codenames, TTP profiles, and follow-up tags.",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max actors to return (default 50)."}
            }
        }
    },
    "tag_campaign_actor": {
        "fn": tag_campaign_actor,
        "description": "Tag an attributed campaign actor with follow-up directives (e.g. ['firewall-block', 'monitor-ssh']) and investigation notes.",
        "parameters": {
            "type": "object",
            "properties": {
                "actor_id": {"type": "string", "description": "The campaign actor ID (e.g. 'ACTOR-4B2E')."},
                "followup_tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of follow-up tags or directives (e.g. ['firewall-block', 'monitor-ssh'])."
                },
                "notes": {"type": "string", "description": "Investigation notes or triage context."},
                "codename": {"type": "string", "description": "Optional codename override."},
                "fingerprint": {"type": "string", "description": "Optional technique fingerprint."}
            },
            "required": ["actor_id", "followup_tags"]
        }
    }
}

def run_builtin_stdio():
    """Runs standard Model Context Protocol (2024-11-05) JSON-RPC over stdin/stdout."""
    sys.stderr.write(f"[LogNode MCP] Built-in stdio engine started (LogNode URL: {LOGNODE_URL})\n")
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            sys.stderr.write(f"[LogNode MCP] JSON parse error: {e}\n")
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            proto = params.get("protocolVersion", "2024-11-05")
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": proto,
                    "capabilities": {
                        "tools": {"listChanged": False}
                    },
                    "serverInfo": {
                        "name": "lognode",
                        "version": "1.0.0"
                    }
                }
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "notifications/initialized":
            # Client ACK notification - no response required
            pass

        elif method == "ping":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "tools/list":
            tools_list = [
                {
                    "name": name,
                    "description": item["description"],
                    "inputSchema": item["parameters"]
                }
                for name, item in TOOL_REGISTRY.items()
            ]
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": tools_list
                }
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            if tool_name not in TOOL_REGISTRY:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool '{tool_name}' not found"
                    }
                }
            else:
                try:
                    result_text = TOOL_REGISTRY[tool_name]["fn"](**tool_args)
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": str(result_text)
                                }
                            ],
                            "isError": False
                        }
                    }
                except Exception as e:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Execution error: {e}"
                                }
                            ],
                            "isError": True
                        }
                    }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif req_id is not None:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not supported"
                }
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


def run_mcp_sdk():
    """Runs with the official MCP Python SDK (MCPServer)."""
    from mcp.server import MCPServer

    server = MCPServer("lognode")
    server.tool()(list_findings)
    server.tool()(get_finding)
    server.tool()(submit_verdict)
    server.tool()(triage_summary)
    server.tool()(query_logs)
    server.tool()(get_fleet_stats)
    server.tool()(list_templates)
    server.tool()(sync_storage)
    server.tool()(ingest_log)
    server.tool()(get_anomalies)
    server.tool()(get_traffic_graph)
    server.tool()(get_traffic_shifts)
    server.tool()(get_subgraph)
    server.tool()(get_host_flows)
    server.tool()(get_time_lapse)
    server.tool()(query_graphql)
    server.tool()(list_campaign_actors)
    server.tool()(tag_campaign_actor)
    server.tool()(test_discord_alert)

    sys.stderr.write(f"[LogNode MCP] Official SDK server running (LogNode URL: {LOGNODE_URL})\n")
    sys.stderr.flush()
    server.run(transport="stdio")


def main():
    # If MCP SDK is available and not disabled by environment, use it.
    # Otherwise smoothly use the zero-dependency pure Python JSON-RPC engine.
    force_builtin = os.environ.get("LOGNODE_MCP_BUILTIN", "").lower() in ("1", "true", "yes")
    if not force_builtin:
        try:
            import mcp.server # noqa: F401
            run_mcp_sdk()
            return
        except ImportError:
            pass

    run_builtin_stdio()


if __name__ == "__main__":
    main()
