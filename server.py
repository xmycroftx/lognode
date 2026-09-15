#!/usr/bin/env python3
import os
import asyncio
import json
import re
import socket
import time
from pathlib import Path
from aiohttp import web
from engine import AsyncLogPipeline

DASHBOARD_FILE = Path(__file__).parent / "dashboard.html"
SEARCH_FILE = Path(__file__).parent / "search.html"

pipeline = AsyncLogPipeline()
START_TIME = time.time()

# ----------------- UDP Syslog Protocol -----------------
class UDPSyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr):
        try:
            text = data.decode("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line:
                    asyncio.create_task(pipeline.ingest(line, extra_labels={"protocol": "udp", "remote_ip": addr[0]}))
        except Exception as e:
            print(f"[UDP] Error processing packet from {addr}: {e}")

# ----------------- HTTP Handlers -----------------
async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({
        "status": "healthy",
        "uptime_s": round(time.time() - START_TIME, 1),
        "templates_loaded": len(pipeline.matcher.rules),
        "postgres_connected": pipeline.pg.pool is not None,
        "pg_queue_size": pipeline.pg.queue.qsize() if pipeline.pg else 0,
        "clusterer_buckets": len(pipeline.clusterer.buckets) if pipeline.clusterer else 0,
        "calibration": pipeline.anomaly_detector.calibration_status if hasattr(pipeline, "anomaly_detector") else {},
        "graph": {
            "nodes": len(pipeline.graph.nodes),
            "edges": len(pipeline.graph.edges),
            "shifts": len(pipeline.graph.shifts)
        } if hasattr(pipeline, "graph") else {},
        "stats": pipeline.stats
    })

async def handle_templates(request: web.Request) -> web.Response:
    rules = [
        {
            "event": r.event,
            "pattern": r.pattern,
            "fields": r.fields,
            "hit_count": r.hit_count,
            "created_at": r.created_at
        }
        for r in pipeline.matcher.rules
    ]
    return web.json_response(rules)

async def handle_query(request: web.Request) -> web.Response:
    """Query structured events directly from Postgres with rich filters."""
    event = request.query.get("event")
    instance = request.query.get("instance")
    source = request.query.get("source")
    q = request.query.get("q")
    # ?value= finds an address/user/id under ANY kv key on ANY host -- the
    # "where has this IP ever appeared" question. ?kv=key:value pins the role.
    # ?ip= is an alias for value=, because that is what it gets used for.
    value = request.query.get("value") or request.query.get("ip")
    kv = request.query.get("kv")
    since = request.query.get("since")

    since_s = None
    if since:
        try:
            if since.endswith("m"):
                since_s = int(since[:-1]) * 60
            elif since.endswith("h"):
                since_s = int(since[:-1]) * 3600
            elif since.endswith("d"):
                since_s = int(since[:-1]) * 86400
            elif since.endswith("s"):
                since_s = int(since[:-1])
            else:
                since_s = int(since)
        except ValueError:
            pass

    try:
        limit = min(int(request.query.get("limit", 50)), 1000)
    except ValueError:
        limit = 50

    t0 = time.perf_counter()
    try:
        rows = await pipeline.pg.query_logs(
            event=event,
            instance=instance,
            source=source,
            q=q,
            value=value,
            kv=kv,
            since_s=since_s,
            limit=limit
        )
    except ValueError as exc:
        # A rejected filter is the caller's mistake, not a server fault, and
        # saying which is the difference between a usable API and a mystery.
        return web.json_response({"error": str(exc)}, status=400)
    query_time_ms = round((time.perf_counter() - t0) * 1000, 2)

    return web.json_response({
        "count": len(rows),
        "query_time_ms": query_time_ms,
        "filters": {
            "event": event,
            "instance": instance,
            "source": source,
            "q": q,
            "value": value,
            "kv": kv,
            "since_s": since_s
        },
        "events": rows
    })

async def handle_sync(request: web.Request) -> web.Response:
    """Checkpoints Postgres and snapshots RAM tmpfs to NVMe persistent storage."""
    t0 = time.perf_counter()
    try:
        if pipeline.pg.pool:
            async with pipeline.pg.pool.acquire() as conn:
                await conn.execute("CHECKPOINT;")

        proc = await asyncio.create_subprocess_shell(
            "podman unshare rsync -a --delete /dev/shm/lognode/pgdata/ ./pgdata.persistent/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            return web.json_response({"error": stderr.decode()}, status=500)

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return web.json_response({
            "status": "persisted",
            "sync_time_ms": elapsed_ms,
            "target": str(Path(__file__).resolve().parent / "pgdata.persistent")
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

async def handle_sync_templates(request: web.Request) -> web.Response:
    """Merges runtime-learned templates into base templates.json and commits to git if requested."""
    do_commit = request.query.get("commit", "false").lower() in ("true", "1", "yes")
    result = pipeline.matcher.sync_to_base(commit_to_git=do_commit)
    return web.json_response(result)

async def handle_metrics(request: web.Request) -> web.Response:
    """Exposes Prometheus exposition format for Grafana Alloy scrape."""
    lines = []
    # Ingest stats
    lines.append("# HELP lognode_ingest_total Total logs ingested")
    lines.append("# TYPE lognode_ingest_total counter")
    lines.append(f"lognode_ingest_total {pipeline.stats.get('total_ingested', 0)}")

    lines.append("# HELP lognode_hotpath_matches_total Total hotpath regex matches")
    lines.append("# TYPE lognode_hotpath_matches_total counter")
    lines.append(f"lognode_hotpath_matches_total {pipeline.stats.get('hot_path_matches', 0)}")

    lines.append("# HELP lognode_coldpath_buffered_total Total coldpath buffered logs")
    lines.append("# TYPE lognode_coldpath_buffered_total counter")
    lines.append(f"lognode_coldpath_buffered_total {pipeline.stats.get('cold_path_buffered', 0)}")

    lines.append("# HELP lognode_templates_synthesized_total Total templates synthesized by LLM")
    lines.append("# TYPE lognode_templates_synthesized_total counter")
    lines.append(f"lognode_templates_synthesized_total {pipeline.stats.get('templates_synthesized', 0)}")

    lines.append("# HELP lognode_templates_active Total active regex templates")
    lines.append("# TYPE lognode_templates_active gauge")
    lines.append(f"lognode_templates_active {len(pipeline.matcher.rules)}")

    lines.append("# HELP lognode_queue_depth Current PostgreSQL flusher queue depth")
    lines.append("# TYPE lognode_queue_depth gauge")
    q_size = pipeline.pg.queue.qsize() if pipeline.pg else 0
    lines.append(f"lognode_queue_depth {q_size}")

    lines.append("# HELP lognode_cluster_buckets Active skeleton clustering buckets")
    lines.append("# TYPE lognode_cluster_buckets gauge")
    b_size = len(pipeline.clusterer.buckets) if pipeline.clusterer else 0
    lines.append(f"lognode_cluster_buckets {b_size}")

    # Instance totals & anomalies
    if hasattr(pipeline, "anomaly_detector"):
        lines.append("# HELP lognode_events_by_instance Total events in rolling window by instance")
        lines.append("# TYPE lognode_events_by_instance gauge")
        for inst, dq in pipeline.anomaly_detector.instance_total_timestamps.items():
            lines.append(f'lognode_events_by_instance{{instance="{inst}"}} {len(dq)}')

        lines.append("# HELP lognode_anomaly_active Active anomaly indicator (1 if firing)")
        lines.append("# TYPE lognode_anomaly_active gauge")
        for key, anom in pipeline.anomaly_detector.active_anomalies.items():
            inst = anom.get("instance", "unknown")
            ev = anom.get("event", "unknown")
            lines.append(f'lognode_anomaly_active{{instance="{inst}",event="{ev}"}} 1')

    # Graph Topology metrics
    if hasattr(pipeline, "graph"):
        lines.extend(pipeline.graph.get_prometheus_metrics())

    lines.append("")
    return web.Response(text="\n".join(lines), content_type="text/plain; version=0.0.4")

async def handle_anomalies(request: web.Request) -> web.Response:
    """Returns active rate spikes, unstructured surges, or critical alerts."""
    anomalies = []
    calib = {}
    if hasattr(pipeline, "anomaly_detector"):
        anomalies = list(pipeline.anomaly_detector.active_anomalies.values())
        calib = pipeline.anomaly_detector.calibration_status
    return web.json_response({
        "calibration": calib,
        "count": len(anomalies),
        "anomalies": anomalies
    })

async def handle_graph(request: web.Request) -> web.Response:
    """Returns the fleet traffic domain graph (nodes, edges, shifts, summary)."""
    if hasattr(pipeline, "graph"):
        return web.json_response(pipeline.graph.to_dict())
    return web.json_response({"error": "Graph engine not initialized"}, status=503)



# The distinct-instance scan costs ~480ms against 3M rows, which is fine
# occasionally and rude on every page load, so it is cached.
_INSTANCES_CACHE = {"at": 0.0, "names": []}

async def handle_instances(request: web.Request) -> web.Response:
    """Hosts that actually appear in the log index.

    Deliberately NOT the graph's node list: the graph carries declared peers and
    cloud endpoints (chromebook-split, grafana-cloud, home-egress) that never
    ship logs, and a filter offering hosts that can never match is a small lie.
    This also surfaces senders the graph does not know about -- mcp-agent and
    stress-tester show up here and nowhere else.
    """
    now = time.time()
    if now - _INSTANCES_CACHE["at"] < 300 and _INSTANCES_CACHE["names"]:
        return web.json_response({"instances": _INSTANCES_CACHE["names"], "cached": True})
    names = []
    try:
        if pipeline.pg.pool:
            async with pipeline.pg.pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT DISTINCT labels->>'instance' AS i FROM log_events "
                    "WHERE timestamp >= NOW() - (30 * INTERVAL '1 day') "
                    "AND labels ? 'instance'")
            names = sorted(r["i"] for r in rows if r["i"])
            _INSTANCES_CACHE.update(at=now, names=names)
    except Exception as exc:
        return web.json_response({"instances": [], "error": str(exc)})
    return web.json_response({"instances": names, "cached": False})

async def handle_search_ui(request: web.Request) -> web.Response:
    """The search UI. The /query API has been usable from curl for a while and
    unusable from a chair; this is the chair."""
    if SEARCH_FILE.exists():
        return web.Response(text=SEARCH_FILE.read_text(encoding="utf-8"),
                            content_type="text/html")
    return web.json_response({"error": "search.html not found"}, status=404)

async def handle_graph_subgraph(request: web.Request) -> web.Response:
    """The connected neighbourhood around an address, host, or node id.

    /graph/subgraph?ip=127.0.0.1&depth=1
    /graph/subgraph?node=vault-host&depth=2&format=mermaid

    Pairs with /query?ip= : that one finds where an address appears in the log
    index, this one finds what it is connected to in the topology.
    """
    if not hasattr(pipeline, "graph"):
        return web.json_response({"error": "graph not available"}, status=503)

    ident = request.query.get("ip") or request.query.get("node") or request.query.get("q")
    if not ident:
        return web.json_response(
            {"error": "pass ip=, node= or q= -- an address, hostname or node id"},
            status=400)

    try:
        depth = int(request.query.get("depth", 1))
    except ValueError:
        return web.json_response({"error": "depth must be an integer"}, status=400)

    result = pipeline.graph.subgraph(ident, depth=depth)

    fmt = request.query.get("format")
    if fmt == "mermaid":
        return web.Response(text=result.get("mermaid", ""),
                            content_type="text/plain", charset="utf-8")
    if fmt == "json":
        return web.json_response(result)

    # A browser asking for this URL wants to SEE the neighbourhood. Returning
    # mermaid source to a browser is technically an answer and practically a
    # blank stare, so render it. Tools still get JSON: they send Accept: */*.
    if "text/html" in (request.headers.get("Accept") or ""):
        return web.Response(text=_subgraph_page(result),
                            content_type="text/html", charset="utf-8")
    return web.json_response(result)


def _subgraph_page(result: dict) -> str:
    """Self-contained page that draws one neighbourhood."""
    import html as _html

    seed = _html.escape(str(result.get("seed", "")))
    resolved = _html.escape(str(result.get("resolved", "")))
    # NOT html-escaped. Content inside a <script> element is raw text: entities
    # are never decoded there, so escaping would hand mermaid a literal
    # [&quot;Workstations&quot;] and it would refuse to parse. Encode it as a
    # JS string instead, and neutralise "</" so nothing can close the element.
    chart = json.dumps(result.get("mermaid", "")).replace("</", "<\\/")
    if not result.get("found"):
        body = ('<p class="miss"><b>' + seed + '</b> is not a node in the graph.<br>'
                + _html.escape(str(result.get("note", ""))) + '</p>')
    else:
        rows = "".join(
            '<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                _html.escape(str(n.get("id"))), n.get("hops"),
                _html.escape(str(n.get("type", ""))))
            for n in result.get("nodes", []))
        body = ('<div class="meta">seed <b>%s</b> &rarr; resolved <b>%s</b> '
                '&middot; %s nodes &middot; %s edges &middot; depth %s</div>'
                '<div id="d">drawing&hellip;</div>'
                '<table><tr><th>node</th><th>hops</th><th>type</th></tr>%s</table>'
                % (seed, resolved, result.get("node_count"), result.get("edge_count"),
                   result.get("depth"), rows))

    return """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>subgraph: %s</title><style>
body{background:#0a0c10;color:#e5e7eb;font:14px/1.5 ui-sans-serif,system-ui,sans-serif;margin:0;padding:24px}
h1{font-size:16px;margin:0 0 4px}
.meta{color:#9ca3af;font-size:13px;margin-bottom:16px}
.miss{color:#fca5a5}
#d{background:#11141b;border:1px solid #1f2937;border-radius:8px;padding:16px;overflow:auto;min-height:120px}
table{margin-top:20px;border-collapse:collapse;font:12px ui-monospace,monospace}
th,td{text-align:left;padding:4px 14px 4px 0;border-bottom:1px solid #1f2937}
th{color:#9ca3af;font-weight:500}
pre.err{color:#fca5a5;white-space:pre-wrap}
</style></head><body>
<h1>Connected neighbourhood</h1>
%s
<script type="module">
const SRC = %s;
try {
  const m = await import('https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs');
  m.default.initialize({startOnLoad:false, theme:'dark', securityLevel:'loose',
                        flowchart:{useMaxWidth:true, htmlLabels:true, curve:'basis'}});
  const el = document.getElementById('d');
  if (el) {
    const {svg} = await m.default.render('sg', SRC);
    el.innerHTML = svg;
  }
} catch (e) {
  const el = document.getElementById('d');
  if (el) el.innerHTML = '<pre class="err">diagram library did not load: ' + e + '</pre>';
}
</script>
</body></html>""" % (resolved or seed, body, chart)

async def handle_graph_shifts(request: web.Request) -> web.Response:
    """Returns active topology shifts (silent links, surges, novel edges, starvations)."""
    if hasattr(pipeline, "graph"):
        shifts = pipeline.graph.get_shifts()
        return web.json_response({
            "count": len(shifts),
            "shifts": shifts
        })
    return web.json_response({"error": "Graph engine not initialized"}, status=503)

async def handle_graph_mermaid(request: web.Request) -> web.Response:
    """Returns dynamic Mermaid flowchart or interactive Workstation Telemetry Inspector dashboard."""
    if not hasattr(pipeline, "graph"):
        return web.Response(text="Graph engine not initialized", status=503)

    fmt = request.query.get("format", "").lower()
    accept = request.headers.get("Accept", "").lower()
    is_html = (
        fmt == "html"
        or "text/html" in accept
        or request.path in ("/dashboard", "/ui")
    )

    if is_html:
        if DASHBOARD_FILE.exists():
            html = DASHBOARD_FILE.read_text(encoding="utf-8")
            return web.Response(text=html, content_type="text/html")

    chart = pipeline.graph.to_mermaid()
    return web.Response(text=chart, content_type="text/plain", charset="utf-8")

async def handle_alert_test(request: web.Request) -> web.Response:
    """Dispatches a test Discord alert to verify webhook health on demand."""
    from alert import dispatch_discord_alert
    body = {}
    if request.can_read_body:
        try:
            body = await request.json()
        except Exception:
            pass
    res = await dispatch_discord_alert(
        title=body.get("title", "LogNode Manual Alert Test"),
        description=body.get("description", "Manual trigger probe from LogNode API."),
        severity=body.get("severity", "info"),
        instance=body.get("instance", "hub"),
        event=body.get("event", "test_alert"),
        spike_info=body.get("spike_info", "Manual Test Probe"),
        kv=body.get("kv", {"operator": "meatbag"}),
        force=True
    )
    return web.json_response(res)

async def handle_ingest(request: web.Request) -> web.Response:
    content_type = request.content_type.lower()
    results = []
    extra_labels = {"protocol": "http"}

    if "json" in content_type:
        try:
            body = await request.json()
            if isinstance(body, list):
                lines = [str(x) if not isinstance(x, dict) else x.get("line", str(x)) for x in body]
            elif isinstance(body, dict):
                if "labels" in body and isinstance(body["labels"], dict):
                    extra_labels.update(body["labels"])
                if "lines" in body:
                    lines = body["lines"]
                elif "line" in body:
                    lines = [body["line"]]
                else:
                    lines = [json.dumps(body)]
            else:
                lines = [str(body)]
        except Exception as e:
            return web.json_response({"error": f"Invalid JSON: {e}"}, status=400)
    else:
        text = await request.text()
        lines = [l.strip() for l in text.splitlines() if l.strip()]

    for line in lines:
        res = await pipeline.ingest(line, extra_labels=extra_labels)
        results.append(res)

    return web.json_response({"processed": len(results), "results": results})

try:
    import cramjam
except ImportError:
    cramjam = None

def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    res, shift = 0, 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, pos

def _parse_loki_proto(data: bytes) -> list[tuple[str, list[str]]]:
    """Decodes Loki PushRequest protobuf (streams -> labels, entries -> line) in pure Python."""
    pos = 0
    streams = []
    while pos < len(data):
        key, pos = _read_varint(data, pos)
        field_num, wire_type = key >> 3, key & 0x7
        if wire_type == 2:
            length, pos = _read_varint(data, pos)
            chunk = data[pos:pos+length]
            pos += length
            if field_num == 1:  # Stream
                s_pos = 0
                labels = ""
                entries = []
                while s_pos < len(chunk):
                    s_key, s_pos = _read_varint(chunk, s_pos)
                    s_num, s_wire = s_key >> 3, s_key & 0x7
                    if s_wire == 2:
                        s_len, s_pos = _read_varint(chunk, s_pos)
                        s_chunk = chunk[s_pos:s_pos+s_len]
                        s_pos += s_len
                        if s_num == 1:  # labels
                            labels = s_chunk.decode("utf-8", errors="replace")
                        elif s_num == 2:  # Entry
                            e_pos = 0
                            line = ""
                            while e_pos < len(s_chunk):
                                e_key, e_pos = _read_varint(s_chunk, e_pos)
                                e_num, e_wire = e_key >> 3, e_key & 0x7
                                if e_wire == 2:
                                    e_len, e_pos = _read_varint(s_chunk, e_pos)
                                    e_val = s_chunk[e_pos:e_pos+e_len]
                                    e_pos += e_len
                                    if e_num == 2:  # line
                                        line = e_val.decode("utf-8", errors="replace")
                                elif e_wire == 0:
                                    _, e_pos = _read_varint(s_chunk, e_pos)
                                else:
                                    break
                            if line:
                                entries.append(line)
                    elif s_wire == 0:
                        _, s_pos = _read_varint(chunk, s_pos)
                    else:
                        break
                if entries:
                    streams.append((labels, entries))
        elif wire_type == 0:
            _, pos = _read_varint(data, pos)
        else:
            break
    return streams

def _parse_loki_labels(labels_str: str) -> dict:
    if not labels_str:
        return {}
    labels = {}
    for m in re.finditer(r'([a-zA-Z_0-9]+)="([^"]*)"', labels_str):
        labels[m.group(1)] = m.group(2)
    return labels

async def handle_loki_push(request: web.Request) -> web.Response:
    """Loki-compatible push endpoint (POST /loki/api/v1/push) supporting Snappy+Protobuf and JSON."""
    try:
        content_type = request.headers.get("Content-Type", "").lower()
        content_encoding = request.headers.get("Content-Encoding", "").lower()
        raw_body = await request.read()

        if not raw_body:
            return web.Response(status=204)

        if "snappy" in content_encoding or "protobuf" in content_type:
            if not cramjam:
                return web.Response(text="cramjam not installed for snappy", status=500)
            buf = bytes(cramjam.snappy.decompress_raw(raw_body))
            streams = _parse_loki_proto(buf)
            for labels_str, entries in streams:
                parsed_labels = _parse_loki_labels(labels_str)
                for line in entries:
                    asyncio.create_task(pipeline.ingest(line, extra_labels=parsed_labels))
            return web.Response(status=204)

        # Handle standard JSON format
        if "json" in content_type:
            body = json.loads(raw_body.decode("utf-8"))
            streams = body.get("streams", [])
            for stream_obj in streams:
                labels = stream_obj.get("stream", {})
                values = stream_obj.get("values", [])
                for val in values:
                    if len(val) >= 2:
                        asyncio.create_task(pipeline.ingest(val[1], extra_labels=labels))
            return web.Response(status=204)

        return web.Response(text="Unsupported media type", status=415)
    except Exception as e:
        print(f"[LokiPush] Error processing batch: {e}")
        return web.Response(text=str(e), status=400)

async def main():
    loop = asyncio.get_running_loop()

    # Connect to PostgreSQL pool
    await pipeline.start()

    # WireGuard & Localhost interface binding (Option A security)
    bind_hosts_str = os.environ.get("LOGNODE_BIND_HOST", "127.0.0.1,127.0.0.1")
    bind_hosts = [h.strip() for h in bind_hosts_str.split(",") if h.strip()]

    # Start UDP listener on port 1514
    udp_port = int(os.environ.get("LOGNODE_UDP_PORT", "1514"))
    udp_transports = []
    for host in bind_hosts:
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPSyslogProtocol(),
                local_addr=(host, udp_port)
            )
            udp_transports.append(transport)
            print(f"[Network] UDP Syslog listener active on {host}:{udp_port}")
        except OSError as e:
            print(f"[Network] Warning: UDP bind skipped on {host}:{udp_port}: {e}")

    # Setup HTTP application
    app = web.Application()
    app.router.add_get("/health", handle_health)
    app.router.add_get("/stats", handle_health)
    app.router.add_get("/templates", handle_templates)
    app.router.add_get("/query", handle_query)
    app.router.add_get("/search", handle_search_ui)
    app.router.add_get("/instances", handle_instances)
    app.router.add_get("/metrics", handle_metrics)
    app.router.add_get("/anomalies", handle_anomalies)
    app.router.add_get("/graph", handle_graph)
    app.router.add_get("/graph/shifts", handle_graph_shifts)
    app.router.add_get("/graph/subgraph", handle_graph_subgraph)
    app.router.add_get("/graph/mermaid", handle_graph_mermaid)
    app.router.add_get("/dashboard", handle_graph_mermaid)
    app.router.add_get("/ui", handle_graph_mermaid)
    app.router.add_post("/alert/test", handle_alert_test)
    app.router.add_post("/sync", handle_sync)
    app.router.add_post("/sync/templates", handle_sync_templates)
    app.router.add_post("/ingest", handle_ingest)
    app.router.add_post("/loki/api/v1/push", handle_loki_push)

    runner = web.AppRunner(app)
    await runner.setup()
    http_port = int(os.environ.get("LOGNODE_HTTP_PORT", "9514"))
    bound_sites = []
    for host in bind_hosts:
        try:
            site = web.TCPSite(runner, host, http_port)
            await site.start()
            bound_sites.append(f"{host}:{http_port}")
            print(f"[Network] HTTP Ingest / Loki endpoint active on {host}:{http_port}")
        except OSError as e:
            print(f"[Network] Warning: HTTP bind skipped on {host}:{http_port}: {e}")

    if not bound_sites:
        print(f"[Network] ERROR: Failed to bind HTTP on {bind_hosts}! Falling back to 127.0.0.1:{http_port}")
        site = web.TCPSite(runner, "127.0.0.1", http_port)
        await site.start()
        bound_sites.append(f"127.0.0.1:{http_port}")

    print("=" * 65)
    print(f" LOGNODE RUNNING ON {socket.gethostname().upper()} — POSTGRES JSONB ACTIVE")
    print(f" BOUND INTERFACES: {', '.join(bound_sites)}")
    print("=" * 65)

    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
        for t in udp_transports:
            t.close()
        await pipeline.close()

if __name__ == "__main__":
    asyncio.run(main())
