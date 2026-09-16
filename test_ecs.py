#!/usr/bin/env python3
"""ECS mapping: what a Logstash event becomes, and what it must never become.

No database, no server, no Logstash. Everything under test is a pure function of
its arguments, which is the whole reason this file can exist -- the same lesson
as ttp.make_internal_check and findings.should_raise, both of which shipped
inverted while buried in a request handler where nothing could reach them.

The negative cases carry most of the weight here. A mapping that drops a field
does not raise; it produces a slightly emptier row, and the threat engine
downstream scores it confidently and wrongly.
"""
import ecs
import behaviour

ok = True
# A fixed "now" so nothing here depends on the wall clock. It must sit just
# AFTER the fixture timestamps below, or the clamp correctly rejects them as
# future-dated and every mapping assertion fails for the wrong reason.
NOW = 1789520000.0          # 2026-09-16T00:53:20Z


def check(label, cond, detail=""):
    global ok
    print("  %-62s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        ok = False


# --- flatten: Logstash emits either shape, sometimes in one batch ------------
nested = {"host": {"name": "web1"}, "url": {"path": "/x"}}
dotted = {"host.name": "web1", "url.path": "/x"}
check("nested and dotted flatten identically",
      ecs.flatten(nested) == ecs.flatten(dotted), "%r" % (ecs.flatten(nested),))
check("mixed nested+dotted merges rather than clobbering",
      ecs.flatten({"host.name": "a", "host": {"hostname": "b"}}) ==
      {"host.name": "a", "host.hostname": "b"})
check("a list is a value, not a branch to descend",
      ecs.flatten({"tags": ["a", "b"]}) == {"tags": ["a", "b"]})
check("an empty dict does not vanish into nothing",
      ecs.flatten({"a": {}}) == {"a": {}})

# --- a realistic nginx event from Filebeat ----------------------------------
NGINX = {
    "@timestamp": "2026-09-16T00:00:00.123Z",
    "message": '203.0.113.9 - - [16/Sep/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 134 "-" "curl/8"',
    "host": {"name": "web1"},
    "event": {"dataset": "nginx.access"},
    "source": {"ip": "203.0.113.9", "port": 51234},
    "url": {"path": "/.env"},
    "http": {"request": {"method": "GET"}, "version": "1.1",
             "response": {"status_code": 404}},
    "user_agent": {"original": "curl/8"},
}
m = ecs.map_event(NGINX, now=NOW)
check("a well-formed event maps", m is not None)
check("instance comes from host.name", m["labels"]["instance"] == "web1")
check("source and event name come from event.dataset",
      m["labels"]["source"] == "nginx.access" and m["event"] == "nginx.access")
check("raw is the message, not a JSON dump of the document",
      m["raw"].startswith("203.0.113.9 - - ["))

# --- THE trap: status must be a string --------------------------------------
# behaviour._tells counts the consecutive-404 run with `s == "404"`, a bare
# compare with no str(). ECS carries status_code as a JSON integer, so an int
# here scores every wordlist walk as zero 404s -- silently, with no error.
check("parsed status is a str, not the int ECS sent",
      isinstance(m["parsed"]["status"], str), "got %r" % type(m["parsed"]["status"]))
check("parsed status compares equal to '404'", m["parsed"]["status"] == "404")
check("kv status is a str too", isinstance(m["kv"]["status"], str))

# --- the pinning assertion: the two paths must not drift --------------------
# The same request, expressed as a raw nginx line and as an ECS document, must
# reach the threat engine as the same thing. Without this, the structured and
# raw paths diverge and only one of them stays correct.
raw_parsed = behaviour.parse_line(NGINX["message"])
ecs_parsed = m["parsed"]
for k in ("ip", "method", "path", "proto", "status", "ua"):
    check("parsed.%-8s matches the raw-line parse" % k,
          raw_parsed[k] == ecs_parsed[k],
          "raw=%r ecs=%r" % (raw_parsed[k], ecs_parsed[k]))

# --- ttp reads kv directly; these are the names it looks for ----------------
import ttp
hit = ttp._event_to_hit({"kv": m["kv"], "labels": m["labels"], "raw": ""})
check("ttp resolves the event from kv alone, without touching raw",
      hit is not None and hit["ip"] == "203.0.113.9" and hit["path"] == "/.env",
      "%r" % (hit,))

# --- instance fallbacks -----------------------------------------------------
check("host.hostname is used when host.name is absent",
      ecs.map_event({"message": "x", "host": {"hostname": "h2"}})["labels"]["instance"] == "h2")
check("agent.hostname is the last resort",
      ecs.map_event({"message": "x", "agent": {"hostname": "a1"}})["labels"]["instance"] == "a1")
check("host.name wins over agent.hostname",
      ecs.map_event({"message": "x", "host": {"name": "h"},
                     "agent": {"hostname": "a"}})["labels"]["instance"] == "h")
check("no host at all leaves instance unset rather than inventing 'unknown'",
      "instance" not in ecs.map_event({"message": "x"})["labels"])
check("no dataset falls back to 'unstructured'",
      ecs.map_event({"message": "x"})["event"] == "unstructured")

# --- parsed is all-or-nothing ----------------------------------------------
# profile() indexes p["ip"] and p["path"] with no default, so a half-filled
# dict is a KeyError in the threat view, not a missing data point.
check("an event with no HTTP fields has parsed=None",
      ecs.map_event({"message": "just a log line", "host": {"name": "h"}})["parsed"] is None)
check("ip without path yields parsed=None",
      ecs.map_event({"message": "x", "source": {"ip": "1.2.3.4"}})["parsed"] is None)
check("path without ip yields parsed=None",
      ecs.map_event({"message": "x", "url": {"path": "/a"}})["parsed"] is None)

# --- passthrough ------------------------------------------------------------
m2 = ecs.map_event({"message": "x", "host": {"name": "h"},
                    "log": {"level": "warn"}, "process": {"name": "sshd", "pid": 42}})
check("unmapped fields land in kv under their dotted names",
      m2["kv"].get("log.level") == "warn" and m2["kv"].get("process.name") == "sshd")
check("claimed fields are not duplicated into kv",
      "host.name" not in m2["kv"] and "message" not in m2["kv"])

# --- an event with no message still needs a raw (the column is NOT NULL) ----
m3 = ecs.map_event({"source": {"ip": "1.2.3.4"}, "url": {"path": "/a"},
                    "http": {"response": {"status_code": 200}}})
check("a message-less HTTP event still produces a non-empty raw",
      bool(m3["raw"]), "%r" % m3["raw"])
check("the synthetic raw re-parses to the same request",
      (behaviour.parse_line(m3["raw"]) or {}).get("path") == "/a",
      "%r -> %r" % (m3["raw"], behaviour.parse_line(m3["raw"])))
check("an event with neither message nor HTTP fields is rejected outright",
      ecs.map_event({"host": {"name": "h"}}) is None)
check("an empty document is rejected", ecs.map_event({}) is None)

# --- timestamps -------------------------------------------------------------
check("ISO with Z parses", ecs.parse_ts("2026-09-16T00:00:00Z") is not None)
check("ISO with an offset parses", ecs.parse_ts("2026-09-16T02:00:00+02:00") ==
      ecs.parse_ts("2026-09-16T00:00:00Z"))
check("fractional seconds parse", ecs.parse_ts("2026-09-16T00:00:00.123Z") is not None)
check("epoch seconds pass through", ecs.parse_ts(1789000000) == 1789000000.0)
check("epoch milliseconds are detected and scaled",
      ecs.parse_ts(1789000000123) == 1789000000.123)
check("absent is None", ecs.parse_ts(None) is None)
check("unparseable is None, not an exception", ecs.parse_ts("tuesday") is None)

# the asymmetry, stated as tests
ts, susp = ecs.clamp_ts(NOW + 86400, now=NOW)
check("an hour-plus in the future is clamped", ts is None and susp == NOW + 86400)
ts, susp = ecs.clamp_ts(NOW - 20 * 86400, now=NOW)
check("TWENTY DAYS OLD IS KEPT UNCHANGED (a queue replay, not an error)",
      ts == NOW - 20 * 86400 and susp is None, "got ts=%r susp=%r" % (ts, susp))
ts, susp = ecs.clamp_ts(NOW - 400 * 86400, now=NOW)
check("even a year old is kept -- age is not evidence of error", ts is not None)
ts, susp = ecs.clamp_ts(0.0, now=NOW)
check("epoch 0 is refused (a broken parser, not history)", ts is None and susp == 0.0)
check("a clamped timestamp is recorded in kv as _ts_suspect",
      ecs.map_event({"message": "x", "@timestamp": "2400-01-01T00:00:00Z"},
                    now=NOW)["kv"].get("_ts_suspect") is not None)
check("a good timestamp leaves no _ts_suspect marker",
      "_ts_suspect" not in ecs.map_event(NGINX, now=NOW)["kv"])


# --- admission: the four corners --------------------------------------------
# A refusal Logstash retries is not data loss. A 200 over a dead sink is.
check("pool down with an EMPTY queue still refuses (503)",
      ecs.should_shed(0, 50000, pool_up=False) == 503)
check("pool down outranks queue depth", ecs.should_shed(0, 50000, False) == 503)
check("healthy and empty accepts", ecs.should_shed(0, 50000, True) is None)
check("just under the watermark accepts", ecs.should_shed(39999, 50000, True) is None)
check("exactly at the watermark refuses (boundary is >=, not >)",
      ecs.should_shed(40000, 50000, True) == 429)
check("a full queue refuses, never accepts",
      ecs.should_shed(50000, 50000, True) == 429)
check("both refusal codes are in Logstash's retryable set",
      {503, 429} <= {429, 500, 502, 503, 504})

# --- auth -------------------------------------------------------------------
check("no token configured means open", ecs.check_auth(None, None) is True)
check("no token configured ignores a supplied header",
      ecs.check_auth("Bearer whatever", "") is True)
check("configured token accepts the right bearer",
      ecs.check_auth("Bearer s3cret", "s3cret") is True)
check("the Bearer prefix is optional", ecs.check_auth("s3cret", "s3cret") is True)
check("configured token rejects the wrong one",
      ecs.check_auth("Bearer nope", "s3cret") is False)
check("configured token rejects a MISSING header (the inversion case)",
      ecs.check_auth(None, "s3cret") is False)
check("configured token rejects an EMPTY header",
      ecs.check_auth("", "s3cret") is False)

# --- decode_batch -----------------------------------------------------------
import gzip as _gz, json as _js
one = {"message": "a"}
check("a json_batch array decodes", ecs.decode_batch(_js.dumps([one, one]).encode()) == [one, one])
check("a single object decodes to a one-element list",
      ecs.decode_batch(_js.dumps(one).encode()) == [one])
check("genuinely gzipped bytes are decompressed",
      ecs.decode_batch(_gz.compress(_js.dumps([one]).encode()),
                       content_encoding="gzip") == [one])
# aiohttp decompresses request bodies itself, so the handler usually sees plain
# text WITH the gzip header still set. Trusting the header here rejected every
# real Logstash batch with a 400, which Logstash does not retry.
check("a gzip HEADER on an already-decompressed body is not an error",
      ecs.decode_batch(_js.dumps([one]).encode(), content_encoding="gzip") == [one])
check("gzipped bytes with NO header are still decompressed",
      ecs.decode_batch(_gz.compress(_js.dumps([one]).encode())) == [one])
check("ndjson decodes, blank lines ignored",
      ecs.decode_batch(b'{"message":"a"}\n\n{"message":"b"}\n',
                       content_type="application/x-ndjson") ==
      [{"message": "a"}, {"message": "b"}])
check("an empty body is zero events, not an error", ecs.decode_batch(b"  ") == [])

for bad, why in ((b"{not json", "malformed json"),
                 (b'["a","b"]', "an array of strings, not objects"),
                 (b"\x1f\x8bnotgzip", "corrupt gzip")):
    try:
        ecs.decode_batch(bad, content_encoding="gzip" if bad.startswith(b"\x1f") else "")
        check("BadBatch raised for %s" % why, False, "it did not raise")
    except ecs.BadBatch:
        check("BadBatch raised for %s" % why, True)


# --- Loki entry timestamps ----------------------------------------------------
check("nanosecond string -> epoch seconds", ecs.loki_ns("1789516800123456789") == 1789516800.123456789)
check("integer nanoseconds accepted", ecs.loki_ns(1789516800000000000) == 1789516800.0)
check("zero is absent, not 1970", ecs.loki_ns("0") is None)
check("garbage is None, not an exception", ecs.loki_ns("now") is None and ecs.loki_ns(None) is None)

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
