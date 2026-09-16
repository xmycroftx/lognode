#!/usr/bin/env python3
"""loki_tail: each entry once, with its own time, and LogNode's 429 is a hold.

The pure helpers are tested directly. The I/O is tested against an in-process
mock Loki and mock LogNode on loopback, so the real request code runs without
a token or a network: two pages of query_range, a LogNode that says 429 once
before accepting, and a cursor that must survive a restart.
"""
import asyncio
import json
import os
import tempfile

import loki_tail as L

ok = True


def check(label, cond, detail=""):
    global ok
    print("  %-66s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        ok = False


# --- pure -----------------------------------------------------------------
check("15m -> 900", L.parse_duration("15m") == 900)
check("2h -> 7200", L.parse_duration("2h") == 7200)
check("bare seconds", L.parse_duration("45") == 45)
check("empty -> default", L.parse_duration("", 900) == 900)
try:
    L.parse_duration("soon"); check("garbage raises", False)
except ValueError:
    check("garbage raises", True)

u = L.tail_url("https://logs.example.net/", '{job="x"}', start_ns=5, delay_for=1)
check("tail url is wss on the loki tail path", u.startswith("wss://logs.example.net/loki/api/v1/tail?"), u)
check("tail url carries query, start and delay_for",
      "query=%7Bjob%3D%22x%22%7D" in u and "start=5" in u and "delay_for=1" in u, u)
check("http -> ws", L.tail_url("http://h", "{}").startswith("ws://h/"))
r = L.range_url("https://h", "{}", 1, 2)
check("range url is forward and bounded", "direction=forward" in r and "start=1" in r and "end=2" in r)

tail_msg = {"streams": [{"stream": {"job": "a"}, "values": [["20", "second"], ["10", "first"]]}]}
range_msg = {"data": {"result": [{"stream": {"job": "a"}, "values": [["10", "first"]]}]}}
check("tail shape parsed and time-ordered", [e[2] for e in L.entries_from(tail_msg)] == ["first", "second"])
check("query_range shape parsed", L.entries_from(range_msg) == [({"job": "a"}, 10, "first")])
check("malformed values are skipped, not fatal",
      L.entries_from({"streams": [{"stream": {}, "values": [["x", "y"], ["1"]]}]}) == [])

seen = L.Seen(capacity=3)
check("first sight is new", seen.add(1, "a") is True)
check("same ts+line is not", seen.add(1, "a") is False)
check("same line, different ts IS new (a repeated log line is two events)", seen.add(2, "a") is True)
seen.add(3, "b"); seen.add(4, "c")
check("capacity evicts the oldest", seen.add(1, "a") is True)

body = L.to_push_body([({"job": "a"}, 10, "x"), ({"job": "a"}, 11, "y"), ({"job": "b"}, 12, "z")], {"via": "loki"})
check("entries regroup by label set", len(body["streams"]) == 2)
check("via=loki is stamped on every stream", all(s["stream"].get("via") == "loki" for s in body["streams"]))
check("timestamps are forwarded as nanosecond strings",
      body["streams"][0]["values"][0][0] == "10" and isinstance(body["streams"][0]["values"][0][0], str))

check("backoff doubles and caps", L.backoff_s(1) == 1 and L.backoff_s(3) == 4 and L.backoff_s(50) == 60)

tmp = tempfile.mkdtemp()
sf = os.path.join(tmp, "s.json")
check("no cursor file -> None", L.load_cursor(sf) is None)
L.save_cursor(sf, 12345)
check("cursor round-trips", L.load_cursor(sf) == 12345)
check("cursor write is atomic (no .tmp left behind)", not os.path.exists(sf + ".tmp"))


# --- I/O against loopback mocks --------------------------------------------
async def io_test():
    from aiohttp import web
    import aiohttp

    calls = {"range": 0, "push": 0, "push_bodies": []}

    async def query_range(req):
        calls["range"] += 1
        start = int(req.query["start"])
        limit = int(req.query.get("limit", 1000))
        # honour limit, so limit=2 produces two full pages then a short one
        allv = [[str(t), "line %d" % t] for t in (100, 200, 300, 400, 500)]
        page = [v for v in allv if int(v[0]) >= start][:limit]
        return web.json_response({"data": {"result": [{"stream": {"job": "mock"}, "values": page}]}})

    async def push(req):
        calls["push"] += 1
        body = await req.json()
        if calls["push"] == 1:
            return web.Response(status=429, headers={"Retry-After": "0"})
        calls["push_bodies"].append(body)
        return web.Response(status=204)

    app = web.Application()
    app.router.add_get("/loki/api/v1/query_range", query_range)
    app.router.add_post("/loki/api/v1/push", push)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    port = site._server.sockets[0].getsockname()[1]
    base = "http://127.0.0.1:%d" % port

    async with aiohttp.ClientSession() as session:
        src = L.LokiSource(session, base, '{job="mock"}', token="t")
        fwd = L.Forwarder(session, base + "/loki/api/v1/push")
        state = os.path.join(tmp, "cursor.json")
        L.save_cursor(state, 99)                      # resume just before the first entry
        entries = await src.poll(100, 10**18, limit=2)
        check("poll pages forward until a short page", [e[1] for e in entries] == [100, 200, 300, 400, 500], entries)
        check("three pages were fetched for five entries at limit 2", calls["range"] == 3, calls["range"])

        cursor = await L.run("poll", src, fwd, state, start_back_s=1, poll_s=0, once=True)
        got = [v for b in calls["push_bodies"] for s in b["streams"] for v in s["values"]]
        check("a 429 from LogNode is a hold, then the same batch lands", calls["push"] == 2 and len(got) == 5,
              "push calls=%d delivered=%d" % (calls["push"], len(got)))
        check("forwarded entries keep their own timestamps", [v[0] for v in got] == ["100", "200", "300", "400", "500"])
        check("cursor advanced to the last delivered entry", cursor == 500 and L.load_cursor(state) == 500, cursor)
        check("via=loki stamped", all(s["stream"]["via"] == "loki" for b in calls["push_bodies"] for s in b["streams"]))

        # a second run from the saved cursor must deliver nothing new
        before = fwd.sent
        await L.run("poll", src, fwd, state, start_back_s=1, poll_s=0, once=True)
        check("resuming from the cursor re-sends nothing", fwd.sent == before, fwd.sent - before)
    await runner.cleanup()

asyncio.run(io_test())

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
