#!/usr/bin/env python3
"""ECS events from a Logstash aggregator, mapped to LogNode's shape.

LogNode's own pipeline exists to *derive* structure from unstructured text: a
linear scan over ~1,400 regex templates, and an LLM to synthesize a new one when
nothing matches. A site running Logstash has already done that work with grok
and the Filebeat modules, so an event arriving here is structured on the way in.

Nothing in this module touches the matcher or the templatizer, and that is the
point rather than an optimisation. The matcher's cost is linear in the template
count, and the template count grows with host diversity -- so its ceiling FALLS
as hosts are added. Mapping straight from ECS makes the per-line cost
independent of how many hosts are connected.

Pure functions only: no I/O, no imports from engine or server. The policy that
decides what a log line becomes is exactly the kind of thing that has shipped
inverted in this project twice while buried in a request handler.
"""
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

# The clamp is deliberately ASYMMETRIC.
#
# A future timestamp is always wrong -- nothing has happened yet -- and it does
# lasting damage: every query in this codebase is ORDER BY timestamp DESC, so a
# row dated 2030 sits at the top of all of them forever, and no retention sweep
# will ever be old enough to remove it. One host with a broken RTC poisons the
# whole view. So the future is clamped hard.
#
# The past is NOT clamped by age. A shipper draining a persistent queue after an
# outage legitimately sends events that are days or weeks old -- honouring that
# is the entire reason this module reads @timestamp instead of taking ingest
# time. Rewriting them to now() would reintroduce exactly the bug this feature
# exists to fix. Only a timestamp before 2000 is refused, because that is a
# broken parser returning epoch 0, not history.
MAX_FUTURE_SECONDS = 300
EPOCH_FLOOR = 946684800.0   # 2000-01-01T00:00:00Z


def flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Nested ECS -> dotted keys. Already-dotted keys pass through untouched.

    Logstash emits either shape depending on configuration, and the same
    pipeline can emit both in one batch, so accepting only one of them produces
    a receiver that works in testing and silently drops fields in production.
    """
    out: Dict[str, Any] = {}
    if not isinstance(obj, dict):
        return out
    for k, v in obj.items():
        key = "%s.%s" % (prefix, k) if prefix else str(k)
        # A list is a value (ECS `tags`, `related.ip`), not a branch to descend.
        if isinstance(v, dict) and v:
            out.update(flatten(v, key))
        else:
            out[key] = v
    return out


def _first(f: Dict[str, Any], *keys: str) -> Optional[Any]:
    """First key present with a non-empty value. Order is the preference order."""
    for k in keys:
        v = f.get(k)
        if v is not None and v != "":
            return v
    return None


def parse_ts(value: Any) -> Optional[float]:
    """ECS @timestamp -> epoch seconds. Accepts ISO-8601 or a numeric epoch."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Milliseconds are common enough to be worth detecting: an epoch in
        # seconds will not plausibly exceed year 5138.
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def clamp_ts(ts: Optional[float], now: Optional[float] = None
             ) -> Tuple[Optional[float], Optional[float]]:
    """-> (timestamp_to_store, suspect_original).

    An absurd timestamp is replaced, never dropped. Discarding a log line over
    clock skew loses evidence. So the event survives with ingest time, and the
    original is recorded so the skew is visible rather than laundered.

    A merely OLD timestamp is not absurd and passes through untouched -- see the
    asymmetry note above.
    """
    if ts is None:
        return None, None
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    if ts > now + MAX_FUTURE_SECONDS or ts < EPOCH_FLOOR:
        return None, ts
    return ts, None


# --- the fields the threat engines actually consume -------------------------
#
# behaviour.parse_line returns exactly these keys, and behaviour.profile reads
# them positionally by name. Building the same dict here is what lets an ECS
# event reach the TTP classifier and the deception scoring without any of them
# knowing where it came from.
_UA = ("user_agent.original", "http.request.headers.user-agent")
_IP = ("source.ip", "client.ip", "source.address", "client.address")
_PATH = ("url.path", "url.original", "http.request.uri")
_METHOD = ("http.request.method", "http.method")
_STATUS = ("http.response.status_code", "http.status_code")
_REFERER = ("http.request.referrer", "http.request.referer", "referer")
_PORT = ("source.port", "client.port")
_HOST = ("host.name", "host.hostname", "agent.hostname", "agent.name", "beat.hostname")
_DATASET = ("event.dataset", "service.name", "event.module", "fileset.name")

# Keys we map deliberately. They must not also be run through
# fields.normalize_fields, whose renaming is driven by value SHAPE -- it would
# rename url.path to something else entirely and the mapping would be undone.
_CLAIMED = set(_UA + _IP + _PATH + _METHOD + _STATUS + _REFERER + _PORT
               + _HOST + _DATASET) | {"@timestamp", "message", "@version"}


def build_parsed(f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The behaviour.parse_line shape, or None if this is not an HTTP event.

    Returns None rather than a half-filled dict: profile() indexes p["ip"] and
    p["path"] without a default, so a partial dict is a KeyError in the threat
    view rather than a missing data point.
    """
    ip = _first(f, *_IP)
    path = _first(f, *_PATH)
    if not ip or not path:
        return None
    status = _first(f, *_STATUS)
    port = _first(f, *_PORT)
    return {
        "ip": str(ip),
        # profile() does `clf_time(p["when"]) or _ts(ev["timestamp"])`, and
        # clf_time only understands nginx's bracketed format. Leaving this None
        # sends it down the fallback, which reads the event's own timestamp.
        "when": None,
        "method": (str(_first(f, *_METHOD) or "") or None),
        "path": str(path),
        "proto": (str(_first(f, "http.version") or "") or None),
        # STRING, not int. profile() compares `s == "404"` when counting the
        # consecutive-404 run, and ECS carries status_code as an integer, so an
        # int here silently scores every wordlist walk as zero 404s.
        "status": (str(status) if status is not None else None),
        "referer": (str(_first(f, *_REFERER) or "") or None),
        "ua": (str(_first(f, *_UA) or "") or None),
        "sport": (str(port) if port is not None else None),
        "source": "ecs",
    }


def map_event(ev: Dict[str, Any], now: Optional[float] = None
              ) -> Optional[Dict[str, Any]]:
    """One ECS event -> {event, labels, kv, raw, ts, parsed}, or None.

    None means "nothing here to store" -- an event with neither a message nor
    any mapped field. The caller counts these rather than failing the batch:
    Logstash treats a non-2xx as undelivered and will resend the whole batch
    forever, so one unusable event must not become an infinite retry loop.
    """
    if not isinstance(ev, dict) or not ev:
        return None
    f = flatten(ev)

    raw = _first(f, "message", "event.original", "log.original")
    parsed = build_parsed(f)
    if raw is None and parsed is None:
        return None

    ts, suspect = clamp_ts(parse_ts(f.get("@timestamp")), now=now)

    labels = {"protocol": "ecs"}
    inst = _first(f, *_HOST)
    if inst:
        labels["instance"] = str(inst)
    src = _first(f, *_DATASET)
    if src:
        labels["source"] = str(src)

    kv: Dict[str, Any] = {}
    for k, v in f.items():
        if k in _CLAIMED or v is None or v == "":
            continue
        kv[k] = v
    # The mapped fields go in under the names the rest of LogNode already
    # searches by, so `?value=<ip>` finds an ECS row the same way it finds a
    # netsnap one.
    if parsed:
        for dst, src_key in (("ip", "ip"), ("path", "path"), ("method", "method"),
                             ("status", "status"), ("ua", "ua"), ("sport", "sport")):
            if parsed.get(src_key):
                kv[dst] = parsed[src_key]
    if suspect is not None:
        kv["_ts_suspect"] = suspect

    return {
        "event": str(_first(f, *_DATASET) or "unstructured"),
        "labels": labels,
        "kv": kv,
        "raw": str(raw) if raw is not None else _synth_raw(parsed),
        "ts": ts,
        "parsed": parsed,
    }


def _synth_raw(parsed: Optional[Dict[str, Any]]) -> str:
    """A combined-log-format line for an ECS event that carried no `message`.

    `raw` is NOT NULL in the schema and the search UI shows it, so an HTTP event
    without a message still needs one. Rendering it in nginx's format means the
    existing raw-text path can re-parse it identically if it ever needs to --
    the two representations stay convertible rather than diverging.
    """
    if not parsed:
        return ""
    # The defaults are not cosmetic. NGINX_RE requires [A-Z]+ for the method and
    # exactly three digits for the status, so a "-" placeholder in either field
    # produces a line that does not re-parse -- which would quietly break the
    # convertibility this function exists to guarantee.
    return '%s - - [-] "%s %s HTTP/%s" %s 0 "%s" "%s"' % (
        parsed.get("ip") or "0.0.0.0", parsed.get("method") or "GET",
        parsed.get("path") or "/", parsed.get("proto") or "1.1",
        parsed.get("status") or "000", parsed.get("referer") or "-",
        parsed.get("ua") or "-")


# --- admission ---------------------------------------------------------------
#
# Logstash retries 429 and 5xx indefinitely and holds the batch in its own
# persistent queue, so refusing work we cannot do is not dropping it -- it is
# handing durability to the component that already has it. That is why LogNode
# stays best-effort internally and does NOT grow a disk queue of its own.
#
# The alternative is what the existing paths do: accept, return 2xx, and discard
# silently when the sink is down. Logstash then deletes the batch from its
# queue, believing it delivered.

import gzip
import json as _json

HIGH_WATER = 0.80


class BadBatch(ValueError):
    """The body could not be decoded. Never retryable -- see decode_batch."""


def should_shed(qsize: int, maxsize: int, pool_up: bool,
                high_water: float = HIGH_WATER) -> Optional[int]:
    """-> an HTTP status to refuse with, or None to accept.

    Order matters: the pool check comes FIRST. A dead pool with an empty queue
    must not look like a healthy server -- that is precisely the state in which
    every row is discarded.
    """
    if not pool_up:
        return 503
    if maxsize and qsize >= int(maxsize * high_water):
        return 429
    return None


def check_auth(header: Optional[str], expected: Optional[str]) -> bool:
    """True when the request may proceed. No token configured means open.

    Open-by-default matches how this service already runs: bound to WireGuard
    addresses rather than the internet. A deployment that exposes it more widely
    sets the token, and the README says so.
    """
    if not expected:
        return True
    if not header:
        return False
    supplied = header[7:] if header[:7].lower() == "bearer " else header
    # Length-independent compare is not worth it here -- the token is not
    # derived from a secret we are protecting from an oracle -- but constant
    # time costs nothing and removes the question.
    if len(supplied) != len(expected):
        return False
    diff = 0
    for a, b in zip(supplied, expected):
        diff |= ord(a) ^ ord(b)
    return diff == 0


def decode_batch(body: bytes, content_type: str = "",
                 content_encoding: str = "") -> list:
    """Raw request body -> a list of ECS documents.

    Raises BadBatch, which the caller must turn into a 400. That status is
    deliberately NOT in Logstash's retryable set: a body we cannot parse will
    never parse, and returning a retryable code for it produces an infinite
    redelivery loop of the same poison batch.
    """
    # Decide by the BYTES, not the header.
    #
    # aiohttp transparently decompresses a request body when Content-Encoding is
    # set -- verified against the running server: with the header the handler
    # receives "[{", without it the raw 1f 8b. So trusting the header and
    # calling gzip.decompress unconditionally rejects every correctly-formed
    # gzipped batch with a 400, which Logstash does not retry. The magic number
    # is the only thing that actually knows, and it also covers a client that
    # sets the header wrongly in either direction.
    if body[:2] == b"\x1f\x8b":
        try:
            body = gzip.decompress(body)
        except Exception as exc:
            raise BadBatch("gzip: %s" % exc)

    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []

    if "ndjson" in (content_type or "").lower():
        docs = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                docs.append(_json.loads(line))
            except Exception as exc:
                raise BadBatch("ndjson line: %s" % exc)
    else:
        try:
            parsed = _json.loads(text)
        except Exception as exc:
            raise BadBatch("json: %s" % exc)
        docs = parsed if isinstance(parsed, list) else [parsed]

    # A batch of strings is Logstash pointed at the wrong endpoint, or `format`
    # left at "json_lines". Saying so beats storing repr() of each one, which is
    # what /ingest would do -- 200 OK, structure silently gone.
    if any(not isinstance(d, dict) for d in docs):
        raise BadBatch("expected JSON objects; got a non-object element "
                       "(is the Logstash output using format => json_batch?)")
    return docs
