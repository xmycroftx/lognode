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
import schema

DASHBOARD_FILE = Path(__file__).parent / "dashboard.html"
SEARCH_FILE = Path(__file__).parent / "search.html"
THREATS_FILE = Path(__file__).parent / "threats.html"

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

    # Loss and retention. Best-effort storage is a defensible design only
    # while the losses are countable.
    lines.append("# HELP lognode_dropped_no_pool_total Rows discarded because Postgres was unreachable")
    lines.append("# TYPE lognode_dropped_no_pool_total counter")
    lines.append(f"lognode_dropped_no_pool_total {getattr(pipeline.pg, 'dropped_no_pool', 0)}")
    lines.append("# HELP lognode_dropped_flush_error_total Rows discarded when a flush batch failed")
    lines.append("# TYPE lognode_dropped_flush_error_total counter")
    lines.append(f"lognode_dropped_flush_error_total {getattr(pipeline.pg, 'dropped_flush_error', 0)}")
    lines.append("# HELP lognode_retention_deleted_total Rows removed by the retention sweep")
    lines.append("# TYPE lognode_retention_deleted_total counter")
    lines.append(f"lognode_retention_deleted_total {pipeline.stats.get('retention_deleted_total', 0)}")
    lines.append("# HELP lognode_retention_window_seconds Configured retention window (0 = disabled)")
    lines.append("# TYPE lognode_retention_window_seconds gauge")
    lines.append(f"lognode_retention_window_seconds {pipeline.stats.get('retention_window_s', 0)}")

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



async def handle_findings_list(request: web.Request) -> web.Response:
    """Open findings, newest first, `new` at the top."""
    import findings
    try:
        rows = await findings.list_findings(
            pipeline.pg.pool,
            state=request.query.get("state"),
            kind=request.query.get("kind"),
            limit=int(request.query.get("limit", 50)))
        return web.json_response({"count": len(rows), "findings": rows}, dumps=_jdump)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_finding_get(request: web.Request) -> web.Response:
    """One finding with its full evidence -- what a reviewer judges on."""
    import findings
    try:
        row = await findings.get_finding(pipeline.pg.pool, int(request.match_info["id"]))
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=400)
    if not row:
        return web.json_response({"error": "no such finding"}, status=404)
    return web.json_response(row, dumps=_jdump)


async def handle_finding_verdict(request: web.Request) -> web.Response:
    """Record a judgement. Recommended actions are recorded, never executed."""
    import findings
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "expected a JSON body"}, status=400)
    try:
        row = await findings.submit_verdict(
            pipeline.pg.pool,
            finding_id=int(request.match_info["id"]),
            verdict=body.get("verdict", ""),
            rationale=body.get("rationale", ""),
            reviewer=body.get("reviewer", "unknown"),
            severity=body.get("severity"),
            recommended_action=body.get("recommended_action"))
    except ValueError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)
    return web.json_response({"ok": True, "finding": row}, dumps=_jdump)


async def handle_findings_summary(request: web.Request) -> web.Response:
    import findings
    try:
        return web.json_response(await findings.summary(pipeline.pg.pool), dumps=_jdump)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


def _jdump(obj) -> str:
    """Timestamps and UUIDs are not JSON; say so in ISO rather than crashing."""
    return json.dumps(obj, default=str)

async def handle_threats(request: web.Request) -> web.Response:
    """Hostile traffic, clustered by technique and by actor fingerprint.

    /threats?since=24h&limit=5000
    /threats?format=json

    Reads the same index the search UI reads, classifies each request against
    ttp.py, and groups actors that ran the same techniques -- the addresses
    rotate, the tooling does not.
    """
    import ttp

    since = request.query.get("since", "24h")
    # The default has to cover the widest window the page offers, or the widest
    # window is the one that quietly shows the least. 7d is currently ~5.4k
    # access lines; classification is linear and in-process, so headroom here
    # costs a second of CPU, while the absence of it costs an actor.
    try:
        limit = min(int(request.query.get("limit", 50000)), 200000)
    except ValueError:
        limit = 50000

    since_s = None
    mult = {"m": 60, "h": 3600, "d": 86400, "s": 1}
    try:
        since_s = int(since[:-1]) * mult[since[-1]] if since[-1] in mult else int(since)
    except Exception:
        since_s = 86400

    # Access lines are the source: HTTP/1.1 is in every one of them and the raw
    # column is trigram-indexed, so this stays cheap as the table grows.
    rows = await pipeline.pg.query_logs(q="HTTP/1.1", since_s=since_s, limit=limit)
    matched = await pipeline.pg.count_logs(q="HTTP/1.1", since_s=since_s)

    view = ttp.build_threat_view(
        rows, is_internal=ttp.make_internal_check(pipeline.graph))
    view["window"] = since

    # Scanned and matched are separate numbers, and the page shows both. They
    # used to be one, and wrong: the engine clamped every query at 1000 rows no
    # matter what the caller asked for, so a "24h" view was built from the most
    # recent 1000 access lines -- six and a half hours of a twenty-four hour
    # window -- and reported that as the scan. An actor quiet for a day did not
    # appear, and nothing on the page distinguished that from an actor who was
    # never there.
    view["events_scanned"] = len(rows)
    view["events_matched"] = matched
    view["truncated"] = len(rows) < matched
    if view["truncated"]:
        view["truncation_note"] = (
            "showing the most recent %d of %d requests in this window; "
            "raise ?limit= to widen it" % (len(rows), matched))

    # Ownership: ASN, network, country, PTR. Opt-out rather than opt-in, because
    # an unattributed address is barely worth showing -- but it IS an external
    # lookup, so it is bounded to the actors actually displayed and says so.
    want_enrich = (request.query.get("enrich", "1") != "0"
                   and os.environ.get("LOGNODE_ENRICH", "1") != "0")
    if want_enrich and view.get("actors"):
        try:
            import enrich
            top = view["actors"][:int(os.environ.get("LOGNODE_ENRICH_MAX", "200"))]
            # to_thread, not inline: this is blocking socket and resolver I/O,
            # and awaiting blocking work on the loop is what put 104 connections
            # in the accept queue earlier in this project's life.
            await asyncio.to_thread(enrich.enrich_actors, top)
            view["owners"] = enrich.group_by_owner(top)
            view["enriched"] = True
            view["enrichment_source"] = "Team Cymru bulk whois + local resolver"
        except Exception as exc:
            # Never let attribution failure remove the finding.
            print("[Threats] enrichment failed (%s); serving unenriched" % exc)
            view["enriched"] = False
    else:
        view["enriched"] = False

    # Claim vs conduct. Cadence, connection reuse and 404-persistence work on
    # any access log; the User-Agent tells need a log that records one, which
    # uvicorn's default does not -- see the note in behaviour.py.
    try:
        import behaviour
        # Feed the reverse DNS enrichment already resolved, so a crawler claim
        # is verified rather than believed. Without it an actor fetching
        # /.ssh/id_rsa while presenting Googlebot scores zero deception.
        rdns_map = {a["ip"]: a.get("rdns") for a in view.get("actors", [])}
        profiles = behaviour.profile(rows, rdns=rdns_map)
        for a in view.get("actors", []):
            prof = profiles.get(a["ip"])
            if prof:
                a["tells"] = prof["tells"]
                a["inconsistency"] = prof["inconsistency"]
                a["user_agents"] = prof["user_agents"]
                a["peak_rate_per_s"] = prof["peak_rate_per_s"]
                a["connections"] = prof["connections"]
                a["longest_404_run"] = prof["longest_404_run"]
        view["actors"].sort(key=lambda x: (-(x.get("inconsistency") or 0), -x["score"]))
    except Exception as exc:
        print("[Threats] behavioural profiling failed (%s)" % exc)

    # Attach persistent campaign actor follow-up tags
    if pipeline.pg and pipeline.pg.pool:
        try:
            import findings
            saved_actors = await findings.list_campaign_actors(pipeline.pg.pool)
            tag_map = {r["actor_id"]: r for r in saved_actors}
            for c in view.get("campaigns", []):
                aid = c.get("actor_id")
                if aid and aid in tag_map:
                    c["followup_tags"] = tag_map[aid].get("followup_tags") or []
                    c["notes"] = tag_map[aid].get("notes") or ""
                    db_fs = tag_map[aid].get("first_seen")
                    if db_fs:
                        db_fs_str = str(db_fs)
                        if not c.get("first_seen") or db_fs_str < str(c["first_seen"]):
                            c["first_seen"] = db_fs_str
                else:
                    c["followup_tags"] = []
                    c["notes"] = ""
            for a in view.get("actors", []):
                aid = a.get("actor_id")
                if aid and aid in tag_map:
                    a["followup_tags"] = tag_map[aid].get("followup_tags") or []
                    a["notes"] = tag_map[aid].get("notes") or ""
                    db_fs = tag_map[aid].get("first_seen")
                    if db_fs:
                        db_fs_str = str(db_fs)
                        if not a.get("first_seen") or db_fs_str < str(a["first_seen"]):
                            a["first_seen"] = db_fs_str
                else:
                    a["followup_tags"] = []
                    a["notes"] = ""
        except Exception as exc:
            print(f"[Threats] Failed to merge campaign followups: {exc}")

    if request.query.get("format") == "json" or "text/html" not in (request.headers.get("Accept") or ""):
        return web.json_response(view)
    if THREATS_FILE.exists():
        return web.Response(text=THREATS_FILE.read_text(encoding="utf-8"),
                            content_type="text/html")
    return web.json_response(view)

async def handle_list_campaigns(request: web.Request) -> web.Response:
    """Lists attributed campaign actors with long-term TTPs and follow-up tags."""
    if not pipeline.pg or not pipeline.pg.pool:
        return web.json_response({"error": "database not available"}, status=503)
    import findings
    try:
        limit = min(int(request.query.get("limit", 100)), 500)
    except ValueError:
        limit = 100
    rows = await findings.list_campaign_actors(pipeline.pg.pool, limit=limit)
    return web.json_response({"campaign_actors": rows}, dumps=lambda x: json.dumps(x, default=str))

async def handle_tag_campaign(request: web.Request) -> web.Response:
    """Tags a campaign actor with follow-up directives and investigative notes."""
    if not pipeline.pg or not pipeline.pg.pool:
        return web.json_response({"error": "database not available"}, status=503)
    actor_id = request.match_info.get("actor_id")
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "valid JSON body required"}, status=400)

    tags = body.get("followup_tags") or body.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    notes = body.get("notes") or ""
    codename = body.get("codename")
    emoji = body.get("emoji")
    fingerprint = body.get("fingerprint")
    threat_tier = body.get("threat_tier")

    import findings
    row = await findings.tag_campaign_actor(
        pipeline.pg.pool,
        actor_id=actor_id,
        followup_tags=tags,
        notes=notes,
        codename=codename,
        emoji=emoji,
        fingerprint=fingerprint,
        threat_tier=threat_tier
    )
    return web.json_response({"status": "ok", "campaign_actor": row}, dumps=lambda x: json.dumps(x, default=str))

async def handle_search_ui(request: web.Request) -> web.Response:
    """The search UI. The /query API has been usable from curl for a while and
    unusable from a chair; this is the chair."""
    if SEARCH_FILE.exists():
        return web.Response(text=SEARCH_FILE.read_text(encoding="utf-8"),
                            content_type="text/html")
    return web.json_response({"error": "search.html not found"}, status=404)

async def handle_graph_subgraph(request: web.Request) -> web.Response:
    """The connected neighbourhood or incident subgraph around an address, host, port, or protocol.

    /graph/subgraph?ip=127.0.0.1&depth=1
    /graph/subgraph?port=443&since=1h&format=mermaid
    /graph/subgraph?node=vault-host&depth=2&format=mermaid
    """
    if not hasattr(pipeline, "graph"):
        return web.json_response({"error": "graph not available"}, status=503)

    ident = request.query.get("ip") or request.query.get("node") or request.query.get("q")
    port = request.query.get("port")
    protocol = request.query.get("protocol")
    instance = request.query.get("instance") or request.query.get("host")
    process = request.query.get("process")
    status = request.query.get("status")
    since = request.query.get("since") or "1h"

    try:
        depth = int(request.query.get("depth", 1))
    except ValueError:
        return web.json_response({"error": "depth must be an integer"}, status=400)

    from graphql_api import _parse_duration
    since_s = _parse_duration(since)

    historical_events = []
    if pipeline.pg and (since_s or port or protocol or process or (ident and "." in ident)):
        try:
            historical_events = await pipeline.pg.query_network_events(
                ip=ident if (ident and ("." in ident or ":" in ident)) else None,
                port=port,
                instance=instance or (ident if (ident and not "." in ident) else None),
                process=process,
                protocol=protocol,
                since_s=since_s or 3600,
                limit=1000
            )
        except Exception as e:
            print(f"[Subgraph] Historical event query error: {e}")

    result = pipeline.graph.search_subgraph(
        identifier=ident,
        ip=ident if (ident and "." in ident) else None,
        port=port,
        protocol=protocol,
        instance=instance,
        process=process,
        status=status,
        depth=depth,
        since_s=since_s,
        historical_events=historical_events
    )

    fmt = request.query.get("format")
    if fmt == "mermaid":
        return web.Response(text=result.get("mermaid", ""),
                            content_type="text/plain", charset="utf-8")
    if fmt == "json":
        return web.json_response(result)

    if "text/html" in (request.headers.get("Accept") or ""):
        return web.Response(text=_subgraph_page(result),
                            content_type="text/html", charset="utf-8")
    return web.json_response(result)


async def handle_graph_host_flows(request: web.Request) -> web.Response:
    """Directed process-level data flow graph for a single host."""
    if not hasattr(pipeline, "graph"):
        return web.json_response({"error": "graph not available"}, status=503)

    host = request.query.get("host") or request.query.get("node") or request.query.get("instance")
    if not host:
        return web.json_response({"error": "pass host= (e.g. hub, laptop, vault-host)"}, status=400)

    since = request.query.get("since", "1h")
    from graphql_api import _parse_duration
    since_s = _parse_duration(since) or 3600

    historical_events = []
    if pipeline.pg:
        try:
            canon = pipeline.graph.resolve_node_id(host)
            historical_events = await pipeline.pg.query_network_events(
                instance=canon,
                since_s=since_s,
                limit=1000
            )
        except Exception as e:
            print(f"[HostFlows] Error querying network events: {e}")

    result = pipeline.graph.build_host_data_flow(
        host=host,
        since_s=since_s,
        historical_events=historical_events
    )

    fmt = request.query.get("format")
    if fmt == "mermaid":
        return web.Response(text=result.get("mermaid", ""), content_type="text/plain", charset="utf-8")
    return web.json_response(result)


async def handle_graph_time_lapse(request: web.Request) -> web.Response:
    """Discrete time-lapse graph sequence over a time window."""
    if not hasattr(pipeline, "graph"):
        return web.json_response({"error": "graph not available"}, status=503)

    host = request.query.get("host") or request.query.get("instance")
    ip = request.query.get("ip")
    port = request.query.get("port")
    since = request.query.get("since", "1h")
    from graphql_api import _parse_duration
    since_s = _parse_duration(since) or 3600

    try:
        slices = max(3, min(int(request.query.get("slices", 12)), 60))
    except ValueError:
        slices = 12

    historical_events = []
    if pipeline.pg:
        try:
            historical_events = await pipeline.pg.query_network_events(
                instance=host,
                ip=ip,
                port=port,
                since_s=since_s,
                limit=2000
            )
        except Exception as e:
            print(f"[TimeLapse] Error querying network events: {e}")

    result = pipeline.graph.build_time_lapse(
        host=host,
        ip=ip,
        port=port,
        since_s=since_s,
        slices=slices,
        historical_events=historical_events
    )
    return web.json_response(result)


async def handle_graphql_post(request: web.Request) -> web.Response:
    """Executes GraphQL query/mutation from JSON payload."""
    from graphql_api import graphql_engine
    try:
        payload = await request.json()
    except Exception as e:
        return web.json_response({"errors": [{"message": f"Invalid JSON payload: {e}"}]}, status=400)

    query = payload.get("query")
    if not query:
        return web.json_response({"errors": [{"message": "Missing 'query' in GraphQL request."}]}, status=400)

    variables = payload.get("variables")
    operation_name = payload.get("operationName")

    result = await graphql_engine.execute(
        pipeline=pipeline,
        query=query,
        variables=variables,
        operation_name=operation_name
    )
    return web.json_response(result)


async def handle_graphql_get(request: web.Request) -> web.Response:
    """Executes GraphQL query via GET query parameters, or serves interactive GraphQL IDE."""
    from graphql_api import graphql_engine
    accept = request.headers.get("Accept", "").lower()
    is_html = "text/html" in accept or request.query.get("format") == "html"

    query = request.query.get("query")
    if not query:
        if is_html:
            return web.Response(text=_graphql_explorer_page(), content_type="text/html", charset="utf-8")
        return web.json_response({"errors": [{"message": "Missing 'query' parameter."}]}, status=400)

    vars_raw = request.query.get("variables")
    variables = {}
    if vars_raw:
        try:
            variables = json.loads(vars_raw)
        except Exception:
            pass

    op_name = request.query.get("operationName")
    result = await graphql_engine.execute(
        pipeline=pipeline,
        query=query,
        variables=variables,
        operation_name=op_name
    )
    return web.json_response(result)


def _graphql_explorer_page() -> str:
    """Interactive GraphQL console and schema explorer with visual diagram support."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogNode GraphQL Interactive Explorer</title>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        window.mermaid = mermaid;
        mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
    </script>
    <style>
        :root {
            --bg-base: #0a0c10; --bg-surface: #11141c; --bg-card: #161b26;
            --border: #242c3d; --accent-cyan: #38bdf8; --accent-blue: #3b82f6;
            --text-main: #e2e8f0; --text-muted: #8b9bb4;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: var(--bg-base); color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            display: flex; flex-direction: column; height: 100vh; overflow: hidden;
        }
        header {
            display: flex; align-items: center; justify-content: space-between;
            padding: 12px 20px; background: var(--bg-surface); border-bottom: 1px solid var(--border);
        }
        .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.1rem; }
        .controls { display: flex; align-items: center; gap: 10px; }
        .btn {
            background: var(--accent-blue); color: #fff; border: none; padding: 6px 14px;
            border-radius: 6px; font-size: 0.85rem; font-weight: 600; cursor: pointer;
            transition: opacity 0.15s;
        }
        .btn:hover { opacity: 0.85; }
        .btn-outline { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-main); }
        select {
            background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border);
            padding: 6px 10px; border-radius: 6px; font-size: 0.85rem;
        }
        .main-container {
            display: grid; grid-template-columns: 1fr 1fr; flex: 1; overflow: hidden;
        }
        .pane {
            display: flex; flex-direction: column; border-right: 1px solid var(--border);
            height: 100%; overflow: hidden;
        }
        .pane-header {
            padding: 8px 16px; background: var(--bg-surface); border-bottom: 1px solid var(--border);
            font-size: 0.75rem; text-transform: uppercase; font-weight: 600; color: var(--text-muted);
            display: flex; justify-content: space-between; align-items: center;
        }
        textarea {
            flex: 1; background: var(--bg-base); color: #38bdf8; font-family: "JetBrains Mono", monospace;
            font-size: 13px; line-height: 1.5; padding: 14px; border: none; resize: none; outline: none;
        }
        .output-wrapper {
            flex: 1; display: flex; flex-direction: column; overflow: hidden;
        }
        pre#json-output {
            flex: 1; overflow: auto; padding: 14px; background: #0c0f17; color: #a7f3d0;
            font-family: "JetBrains Mono", monospace; font-size: 12px; line-height: 1.4;
        }
        #diagram-preview {
            display: none; flex: 1; overflow: auto; padding: 16px; background: var(--bg-card);
            align-items: center; justify-content: center;
        }
        .tab-btn { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-weight: 600; }
        .tab-btn.active { color: var(--accent-cyan); border-bottom: 2px solid var(--accent-cyan); }
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <span>⚡</span>
            <span>LogNode GraphQL Tool Viewport</span>
        </div>
        <div class="controls">
            <select id="query-presets" onchange="loadPreset()">
                <option value="subgraph">Preset: Incident Subgraph (Port 443 & 1h)</option>
                <option value="hostFlows">Preset: Host Data Flows (hub)</option>
                <option value="timeLapse">Preset: Time-Lapse Slices</option>
                <option value="fleet">Preset: Fleet Summary & Graph</option>
                <option value="searchLogs">Preset: Incident Log Search</option>
            </select>
            <button class="btn" onclick="runQuery()">▶ Execute Query</button>
            <a href="/dashboard" class="btn btn-outline" style="text-decoration:none">📊 Open Viewport Dashboard</a>
        </div>
    </header>

    <div class="main-container">
        <div class="pane">
            <div class="pane-header">GraphQL Query</div>
            <textarea id="query-input" spellcheck="false"></textarea>
        </div>
        <div class="output-wrapper">
            <div class="pane-header">
                <div>
                    <button id="tab-json" class="tab-btn active" onclick="switchTab('json')">JSON Response</button>
                    <button id="tab-diagram" class="tab-btn" onclick="switchTab('diagram')">Mermaid Diagram</button>
                </div>
                <span id="timing-status">Ready</span>
            </div>
            <pre id="json-output">// Click 'Execute Query' to evaluate against schema.graphql</pre>
            <div id="diagram-preview"></div>
        </div>
    </div>

    <script>
        const PRESETS = {
            subgraph: `query IncidentAnalysis {
  subgraph(port: 443, since: "1h", depth: 1) {
    querySummary
    totalFlows
    totalVolume
    nodes {
      id
      name
      type
      status
    }
    edges {
      id
      source { id name }
      target { id name }
      protocol
      rate1m
      strokeWidth
      status
    }
    mermaid
    matchedLogs {
      timestamp
      instance
      event
      raw
    }
  }
}`,
            hostFlows: `query HostDataFlow {
  hostFlows(host: "hub", since: "1h") {
    summary {
      hostId
      hostName
      inboundFlows
      outboundFlows
      inboundRate
      outboundRate
      activeProcesses
    }
    nodes { id name type }
    edges { id protocol rate1m }
    mermaid
  }
}`,
            timeLapse: `query TemporalTimeLapse {
  timeLapse(since: "1h", slices: 6) {
    totalSlices
    since
    slices {
      sliceIndex
      timeLabel
      totalVolume
      bytesPerSec
      activeNodes { id }
      newEdges { id protocol }
      mermaid
    }
  }
}`,
            fleet: `query FleetOverview {
  fleet {
    uptimeSeconds
    summary {
      totalNodes
      totalEdges
      activeShifts
      fleetStatus
    }
    nodes {
      id
      name
      type
      ip
      status
    }
    shifts {
      type
      severity
      message
    }
    mermaid
  }
}`,
            searchLogs: `query IncidentLogs {
  searchLogs(q: "netsnap", since: "1h", limit: 10) {
    count
    queryTimeMs
    events {
      id
      timestamp
      instance
      event
      raw
      kvJson
    }
  }
}`
        };

        let lastResult = null;

        function loadPreset() {
            const key = document.getElementById('query-presets').value;
            document.getElementById('query-input').value = PRESETS[key] || '';
        }

        async function runQuery() {
            const query = document.getElementById('query-input').value.trim();
            const statusEl = document.getElementById('timing-status');
            statusEl.textContent = 'Executing...';
            const t0 = performance.now();

            try {
                const res = await fetch('/graphql', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query })
                });
                const data = await res.json();
                const ms = (performance.now() - t0).toFixed(1);
                statusEl.textContent = `Completed in ${ms} ms`;
                lastResult = data;
                document.getElementById('json-output').textContent = JSON.stringify(data, null, 2);

                // Check for mermaid in response
                let mermaidCode = null;
                if (data.data) {
                    for (const key of Object.keys(data.data)) {
                        if (data.data[key] && data.data[key].mermaid) {
                            mermaidCode = data.data[key].mermaid;
                            break;
                        }
                    }
                }

                if (mermaidCode && window.mermaid) {
                    try {
                        const { svg } = await window.mermaid.render('preview-svg-' + Date.now(), mermaidCode);
                        document.getElementById('diagram-preview').innerHTML = svg;
                    } catch (me) {
                        document.getElementById('diagram-preview').innerHTML = '<pre style="color:#ef4444">' + me + '</pre>';
                    }
                }
            } catch (err) {
                statusEl.textContent = 'Failed';
                document.getElementById('json-output').textContent = 'Error: ' + err.message;
            }
        }

        function switchTab(tab) {
            const jsonOut = document.getElementById('json-output');
            const diagOut = document.getElementById('diagram-preview');
            const tabJson = document.getElementById('tab-json');
            const tabDiag = document.getElementById('tab-diagram');

            if (tab === 'json') {
                jsonOut.style.display = 'block';
                diagOut.style.display = 'none';
                tabJson.className = 'tab-btn active';
                tabDiag.className = 'tab-btn';
            } else {
                jsonOut.style.display = 'none';
                diagOut.style.display = 'flex';
                tabJson.className = 'tab-btn';
                tabDiag.className = 'tab-btn active';
            }
        }

        window.onload = () => {
            loadPreset();
        };
    </script>
</body>
</html>
"""


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

async def handle_dashboard(request: web.Request) -> web.Response:
    """Serves the LogNode Environment Viewport dashboard."""
    if DASHBOARD_FILE.exists():
        html = DASHBOARD_FILE.read_text(encoding="utf-8")
        return web.Response(
            text=html,
            content_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
    return web.Response(text="Dashboard file not found", status=404)

async def handle_graph_mermaid(request: web.Request) -> web.Response:
    """Returns dynamic Mermaid flowchart diagram as plain text."""
    if not hasattr(pipeline, "graph"):
        return web.Response(text="Graph engine not initialized", status=503)

    fmt = request.query.get("format", "").lower()
    if fmt == "html":
        return await handle_dashboard(request)

    chart = pipeline.graph.to_mermaid()
    return web.Response(
        text=chart,
        content_type="text/plain",
        charset="utf-8",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
    )

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

async def handle_ecs_ingest(request: web.Request) -> web.Response:
    """Ingest ECS events from a Logstash `http` output. See README.

    Deliberately a separate route from /ingest. /ingest treats a JSON array as a
    list of LINES and falls back to str(x) for anything that is not a string --
    so a json_batch array of ECS objects posted there is accepted with a 200 and
    stored as Python dict reprs, structure silently gone. That failure surfaces
    days later as "why is the threat view empty". This path refuses loudly
    instead.

    The status codes are the durability design. Logstash retries 429 and 5xx
    indefinitely from its own persistent queue, so refusing work we cannot do
    hands the batch back to the component that can hold it. That is why LogNode
    stays best-effort internally rather than growing a disk queue of its own.
    """
    import ecs

    # Shed FIRST -- before reading the body, before gunzip, before parsing.
    # Checking after the work is done spends exactly the CPU we are shedding.
    shed = ecs.should_shed(pipeline.pg.queue.qsize(),
                           pipeline.pg.queue.maxsize,
                           pipeline.pg.pool is not None)
    if shed:
        return web.json_response(
            {"error": "sink unavailable" if shed == 503 else "queue high water",
             "queued": pipeline.pg.queue.qsize()},
            status=shed, headers={"Retry-After": "5"})

    if not ecs.check_auth(request.headers.get("Authorization"),
                          os.environ.get("LOGNODE_INGEST_TOKEN")):
        return web.json_response({"error": "unauthorized"}, status=401)

    try:
        # aiohttp has usually already decompressed by here; decode_batch
        # decides from the bytes rather than the header, so both cases work.
        docs = ecs.decode_batch(await request.read(),
                                request.headers.get("Content-Type", ""),
                                request.headers.get("Content-Encoding", ""))
    except ecs.BadBatch as exc:
        # 400 is NOT retryable, and that is correct: a body we cannot parse will
        # not parse on the tenth attempt either, and returning a retryable code
        # would put the same poison batch into an infinite redelivery loop.
        return web.json_response({"error": str(exc)}, status=400)

    accepted = skipped = 0
    for doc in docs:
        mapped = ecs.map_event(doc)
        if mapped is None:
            skipped += 1
            continue
        # await, never create_task. The awaiting IS the backpressure; the
        # create_task in handle_loki_push is why that path can accept work it
        # will never store.
        await pipeline.ingest_structured(mapped)
        accepted += 1

    return web.json_response({"received": len(docs), "accepted": accepted,
                              "skipped": skipped})


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


async def findings_sweep():
    """Periodically turn threat actors into findings awaiting triage."""
    import findings as F
    await asyncio.sleep(30)          # let ingest settle after a restart
    while True:
        try:
            if pipeline.pg.pool:
                rows = await pipeline.pg.query_logs(q="HTTP/1.1", since_s=3600, limit=5000)
                if rows:
                    import ttp
                    view = ttp.build_threat_view(
                        rows, is_internal=ttp.make_internal_check(pipeline.graph))
                    actors = view.get("actors") or []
                    if actors:
                        try:
                            import enrich, behaviour
                            await asyncio.to_thread(enrich.enrich_actors, actors[:50])
                            profiles = behaviour.profile(
                                rows, rdns={a["ip"]: a.get("rdns") for a in actors})
                            for a in actors:
                                prof = profiles.get(a["ip"]) or {}
                                a["inconsistency"] = prof.get("inconsistency", 0)
                                a["tells"] = prof.get("tells", [])
                                a["user_agents"] = prof.get("user_agents", [])
                        except Exception as exc:
                            print("[Findings] enrichment during sweep failed: %s" % exc)
                    raised = 0
                    for a in actors:
                        reason = F.should_raise(a)
                        if not reason:
                            continue
                        await F.record(
                            pipeline.pg.pool, kind="threat_actor", subject=a["ip"],
                            instance=(a.get("targets") or ["unknown"])[0],
                            severity_hint=("high" if any(t in a.get("techniques", {})
                                                         for t in F.ESCALATE_ON) else "medium"),
                            evidence={"reason": reason,
                                      "ruleset": getattr(ttp, "RULESET_VERSION", "?"),
                                      **a})
                        raised += 1
                    if raised:
                        print("[Findings] %d threat actor(s) awaiting triage" % raised)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print("[Findings] sweep error: %s" % exc)
        await asyncio.sleep(F.SWEEP_SECONDS)

async def main():
    loop = asyncio.get_running_loop()

    # Connect to PostgreSQL pool
    await pipeline.start()

    # The findings table is created here rather than in the pipeline because a
    # failure to create it must not stop ingest: losing triage is bad, losing
    # the log pipeline is worse.
    try:
        import findings
        if pipeline.pg.pool:
            # log_events first: findings can exist without it, but nothing
            # else can. IF NOT EXISTS throughout, so this is a no-op on a
            # database whose schema was applied by hand.
            try:
                await schema.ensure_schema(pipeline.pg.pool)
                print("[Schema] log_events ready")
            except Exception as exc:
                print("[Schema] could not apply log_events DDL: %s" % exc)
            await findings.ensure_schema(pipeline.pg.pool)
            print("[Findings] table ready")
    except Exception as _exc:
        print("[Findings] schema init failed (%s); triage queue unavailable" % _exc)

    asyncio.create_task(findings_sweep())

    # Retention: off unless LOGNODE_RETENTION is set. A bad value raises here
    # and stops startup, which is the right outcome for a destructive setting.
    window = schema.configured_window()
    if window:
        print("[Retention] enabled: rows older than %ds are removed every %ss"
              % (window, os.environ.get("LOGNODE_RETENTION_SWEEP", "600")))
        asyncio.create_task(schema.retention_loop(
            lambda: pipeline.pg.pool, pipeline.stats, window,
            sweep_s=int(os.environ.get("LOGNODE_RETENTION_SWEEP", "600")),
            batch_rows=int(os.environ.get("LOGNODE_RETENTION_BATCH", "20000"))))
    else:
        print("[Retention] disabled (LOGNODE_RETENTION unset); the table grows forever")

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
    # aiohttp defaults client_max_size to 1 MiB. A Logstash json_batch of a few
    # thousand events exceeds that and comes back 413 -- which is NOT in
    # Logstash's retryable_codes, so it would drop the batch silently rather
    # than retry. Raise the ceiling to something a real batch fits in.
    app = web.Application(client_max_size=32 * 1024 * 1024)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/stats", handle_health)
    app.router.add_get("/templates", handle_templates)
    app.router.add_get("/query", handle_query)
    app.router.add_get("/search", handle_search_ui)
    app.router.add_get("/threats", handle_threats)
    app.router.add_get("/threats/campaigns", handle_list_campaigns)
    app.router.add_post("/threats/campaign/{actor_id}/tag", handle_tag_campaign)
    app.router.add_post("/threats/actor/{actor_id}/tag", handle_tag_campaign)
    app.router.add_get("/findings", handle_findings_list)
    app.router.add_get("/findings/summary", handle_findings_summary)
    app.router.add_get("/findings/{id}", handle_finding_get)
    app.router.add_post("/findings/{id}/verdict", handle_finding_verdict)
    app.router.add_get("/instances", handle_instances)
    app.router.add_get("/metrics", handle_metrics)
    app.router.add_get("/anomalies", handle_anomalies)
    app.router.add_get("/graph", handle_graph)
    app.router.add_get("/graph/shifts", handle_graph_shifts)
    app.router.add_get("/graph/subgraph", handle_graph_subgraph)
    app.router.add_get("/graph/host-flows", handle_graph_host_flows)
    app.router.add_get("/graph/time-lapse", handle_graph_time_lapse)
    app.router.add_get("/graph/mermaid", handle_graph_mermaid)
    app.router.add_get("/dashboard", handle_dashboard)
    app.router.add_get("/ui", handle_dashboard)
    app.router.add_post("/graphql", handle_graphql_post)
    app.router.add_get("/graphql", handle_graphql_get)
    app.router.add_post("/alert/test", handle_alert_test)
    app.router.add_post("/sync", handle_sync)
    app.router.add_post("/sync/templates", handle_sync_templates)
    app.router.add_post("/ingest/ecs", handle_ecs_ingest)
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
