#!/usr/bin/env python3
"""Stream logs OUT of a Loki (Grafana Cloud or self-hosted) INTO LogNode.

Loki is usually the sink. Here it is the source: everything the fleet already
ships to Loki arrives at LogNode's own push endpoint, so the classifier and the
threat view see the whole estate without a second shipper on every host.

Two ways to read, chosen by LOKI_MODE:

  tail   -- the /loki/api/v1/tail WebSocket. Live, one connection, entries as
            they arrive. Cannot read the past, and a dropped socket loses the
            gap unless something fills it.
  poll   -- /loki/api/v1/query_range with a moving cursor. A few seconds behind,
            trivially resumable, and can backfill history.
  auto   -- (default) poll to fill any gap since the saved cursor, then tail;
            on a tail failure, back to poll for the gap, then tail again.

The cursor (last entry timestamp seen) is persisted to LOKI_STATE_FILE so a
restart resumes where it stopped rather than at "now". Every entry is
forwarded with its OWN timestamp -- LogNode honours it -- so a backfill lands
where it happened, not when it was read.

Do not run this alongside a direct Alloy dual-ship of the same hosts: the same
line would arrive twice. Entries forwarded here carry the label via="loki" so
that, if it happens, the duplicates are at least distinguishable.

Configuration (environment):
  LOKI_URL          https://logs-prod-042.grafana.net     (no path)
  LOKI_USER         tenant / instance id for basic auth   (Grafana Cloud)
  LOKI_TOKEN        an access-policy token with logs:read (never logged)
  LOKI_QUERY        LogQL selector, default {job=~".+"}
  LOKI_MODE         auto | tail | poll
  LOKI_START        how far back to begin with no saved cursor, e.g. 1h (default 15m)
  LOKI_POLL_S       poll interval in seconds (default 5)
  LOKI_STATE_FILE   cursor file (default ./loki_tail.state)
  LOGNODE_URL       default http://127.0.0.1:9514/loki/api/v1/push
"""
import asyncio
import hashlib
import json
import os
import sys
import time
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlencode

# --- pure helpers (tested without a network) ---------------------------------

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(spec: str, default_s: int = 900) -> int:
    """'15m', '2h', '90s', '1d' -> seconds. Unitless is seconds."""
    s = (spec or "").strip().lower()
    if not s:
        return default_s
    if s[-1] in _UNITS and s[:-1].isdigit():
        return int(s[:-1]) * _UNITS[s[-1]]
    if s.isdigit():
        return int(s)
    raise ValueError("bad duration %r" % spec)


def tail_url(base: str, query: str, start_ns: Optional[int] = None,
             delay_for: int = 0, limit: int = 1000) -> str:
    """The WebSocket URL for /loki/api/v1/tail. http(s) -> ws(s)."""
    base = base.rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    params: Dict[str, Any] = {"query": query, "limit": limit}
    if start_ns:
        params["start"] = start_ns
    if delay_for:
        params["delay_for"] = delay_for
    return "%s/loki/api/v1/tail?%s" % (base, urlencode(params))


def range_url(base: str, query: str, start_ns: int, end_ns: int, limit: int = 1000) -> str:
    return "%s/loki/api/v1/query_range?%s" % (base.rstrip("/"), urlencode({
        "query": query, "start": start_ns, "end": end_ns,
        "limit": limit, "direction": "forward"}))


def entries_from(payload: Dict[str, Any]) -> List[Tuple[Dict[str, str], int, str]]:
    """Both Loki response shapes -> [(labels, ts_ns, line)] in time order.

    tail messages:        {"streams": [{"stream": {...}, "values": [[ts, line]]}]}
    query_range results:  {"data": {"result": [ ...same shape... ]}}
    """
    streams = payload.get("streams")
    if streams is None:
        streams = (payload.get("data") or {}).get("result") or []
    out: List[Tuple[Dict[str, str], int, str]] = []
    for st in streams:
        labels = st.get("stream") or {}
        for val in st.get("values") or []:
            if len(val) < 2:
                continue
            try:
                ts = int(val[0])
            except (TypeError, ValueError):
                continue
            out.append((labels, ts, str(val[1])))
    out.sort(key=lambda e: e[1])
    return out


class Seen:
    """A bounded set of (ts, line) fingerprints, so an overlap between a poll
    window and a tail -- or two overlapping polls -- forwards each entry once."""

    def __init__(self, capacity: int = 20000):
        self.capacity = capacity
        self._d: "OrderedDict[str, None]" = OrderedDict()

    @staticmethod
    def key(ts_ns: int, line: str) -> str:
        return "%d:%s" % (ts_ns, hashlib.blake2b(line.encode("utf-8", "replace"), digest_size=8).hexdigest())

    def add(self, ts_ns: int, line: str) -> bool:
        """True if new."""
        k = self.key(ts_ns, line)
        if k in self._d:
            return False
        self._d[k] = None
        if len(self._d) > self.capacity:
            self._d.popitem(last=False)
        return True


def to_push_body(entries: Iterable[Tuple[Dict[str, str], int, str]],
                 extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Group entries back into Loki push streams, adding `extra` labels."""
    grouped: Dict[str, Dict[str, Any]] = {}
    for labels, ts, line in entries:
        lab = dict(labels)
        if extra:
            lab.update(extra)
        k = json.dumps(lab, sort_keys=True)
        grouped.setdefault(k, {"stream": lab, "values": []})["values"].append([str(ts), line])
    return {"streams": list(grouped.values())}


def backoff_s(attempt: int, base: float = 1.0, cap: float = 60.0) -> float:
    return float(min(cap, base * (2 ** max(0, attempt - 1))))


def load_cursor(path: str) -> Optional[int]:
    try:
        with open(path) as f:
            v = int(json.load(f).get("cursor_ns", 0))
            return v or None
    except Exception:
        return None


def save_cursor(path: str, cursor_ns: int) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"cursor_ns": cursor_ns, "saved_at": time.time()}, f)
    os.replace(tmp, path)


# --- I/O -----------------------------------------------------------------------

class Forwarder:
    """Pushes entries to LogNode, honouring its backpressure.

    A 429 or 503 from LogNode means "hold that" -- it is the receiver's queue
    watermark, not an error -- so the batch is retried with backoff rather
    than dropped. Anything else non-2xx is logged and the batch is dropped:
    a body LogNode will not accept will not be accepted on the tenth try.
    """

    def __init__(self, session, url: str, extra_labels: Optional[Dict[str, str]] = None):
        self.session = session
        self.url = url
        self.extra = extra_labels or {"via": "loki"}
        self.sent = 0
        self.held = 0
        self.dropped = 0

    async def push(self, entries: List[Tuple[Dict[str, str], int, str]]) -> bool:
        if not entries:
            return True
        body = json.dumps(to_push_body(entries, self.extra)).encode("utf-8")
        attempt = 0
        while True:
            attempt += 1
            try:
                async with self.session.post(self.url, data=body,
                                             headers={"Content-Type": "application/json"}) as r:
                    if r.status in (429, 503):
                        self.held += 1
                        wait = float(r.headers.get("Retry-After") or backoff_s(attempt))
                        print("[loki_tail] LogNode %d, holding %d entries for %.0fs" % (r.status, len(entries), wait))
                        await asyncio.sleep(wait)
                        continue
                    if 200 <= r.status < 300:
                        self.sent += len(entries)
                        return True
                    text = (await r.text())[:200]
                    print("[loki_tail] LogNode %d, dropping %d entries: %s" % (r.status, len(entries), text))
                    self.dropped += len(entries)
                    return False
            except Exception as exc:
                wait = backoff_s(attempt)
                print("[loki_tail] LogNode unreachable (%s), retry in %.0fs" % (exc, wait))
                await asyncio.sleep(wait)


class LokiSource:
    def __init__(self, session, base: str, query: str, auth=None, token: Optional[str] = None):
        self.session = session
        self.base = base.rstrip("/")
        self.query = query
        self.auth = auth
        self.headers = {"Authorization": "Bearer " + token} if (token and not auth) else {}

    async def poll(self, start_ns: int, end_ns: int, limit: int = 1000
                   ) -> List[Tuple[Dict[str, str], int, str]]:
        """All entries in [start, end), paging forward until a short page."""
        out: List[Tuple[Dict[str, str], int, str]] = []
        cur = start_ns
        for _ in range(1000):
            url = range_url(self.base, self.query, cur, end_ns, limit)
            async with self.session.get(url, auth=self.auth, headers=self.headers) as r:
                if r.status != 200:
                    raise RuntimeError("query_range HTTP %d: %s" % (r.status, (await r.text())[:200]))
                page = entries_from(await r.json())
            out.extend(page)
            if len(page) < limit:
                break
            cur = page[-1][1] + 1
        return out

    async def tail(self, start_ns: Optional[int], on_batch, delay_for: int = 0):
        """Run the WebSocket tail until it closes or fails. Raises on failure."""
        import aiohttp
        url = tail_url(self.base, self.query, start_ns, delay_for)
        async with self.session.ws_connect(url, auth=self.auth, headers=self.headers, heartbeat=30) as ws:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    payload = json.loads(msg.data)
                    if payload.get("dropped_entries"):
                        print("[loki_tail] Loki reports dropped entries: %d" % len(payload["dropped_entries"]))
                    await on_batch(entries_from(payload))
                elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSED):
                    raise RuntimeError("tail socket %s" % msg.type.name)


async def run(mode: str, source: LokiSource, fwd: Forwarder, state_file: str,
              start_back_s: int, poll_s: int, seen: Optional[Seen] = None,
              once: bool = False, overlap_s: int = 30) -> int:
    """The main loop. Returns the final cursor. `once` runs a single poll."""
    seen = seen or Seen()
    overlap_ns = int(overlap_s * 1e9)
    polls = [0]
    cursor = load_cursor(state_file) or int((time.time() - start_back_s) * 1e9)

    async def deliver(entries) -> int:
        nonlocal cursor
        fresh = [e for e in entries if seen.add(e[1], e[2])]
        if fresh and await fwd.push(fresh):
            cursor = max(cursor, fresh[-1][1])
            save_cursor(state_file, cursor)
        return len(fresh)

    async def fill_gap() -> int:
        # Poll from a little BEFORE the cursor up to a few seconds ago. Loki
        # accepts entries out of order within its ingester window, so a line
        # timestamped before the cursor can still appear after the poll that
        # passed it; re-reading the overlap and letting the seen-set drop the
        # repeats is what turns "usually complete" into "complete". The tail end
        # stays a couple of seconds short of now for the same reason.
        #
        # Not on the FIRST poll of a process, though: the seen-set is empty
        # after a restart, so an overlap there would re-send up to 30 seconds
        # of entries the previous process already delivered. The first poll
        # resumes exactly at the cursor; the overlap applies from the second.
        end = int((time.time() - 2) * 1e9)
        start = cursor + 1 if polls[0] == 0 else max(1, cursor - overlap_ns)
        polls[0] += 1
        if end <= start:
            return 0
        n = await deliver(await source.poll(start, end))
        return n

    attempt = 0
    while True:
        try:
            if mode in ("poll", "auto"):
                n = await fill_gap()
                if n:
                    print("[loki_tail] poll: %d new entries, cursor %d" % (n, cursor))
                if mode == "poll" or once:
                    if once:
                        return cursor
                    await asyncio.sleep(poll_s)
                    attempt = 0
                    continue
            # tail from the cursor; Loki replays from `start` on connect
            print("[loki_tail] tailing from cursor %d" % cursor)
            await source.tail(cursor + 1, deliver)
            attempt = 0
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            attempt += 1
            wait = backoff_s(attempt, base=2.0)
            print("[loki_tail] %s: %s -- retry in %.0fs" % (mode, exc, wait))
            await asyncio.sleep(wait)


async def main() -> int:
    import aiohttp
    base = os.environ.get("LOKI_URL", "").strip()
    token = os.environ.get("LOKI_TOKEN", "")
    user = os.environ.get("LOKI_USER", "")
    if not base or not token:
        print("loki_tail: LOKI_URL and LOKI_TOKEN are required", file=sys.stderr)
        return 2
    query = os.environ.get("LOKI_QUERY", '{job=~".+"}')
    mode = os.environ.get("LOKI_MODE", "auto").lower()
    if mode not in ("auto", "tail", "poll"):
        print("loki_tail: LOKI_MODE must be auto, tail or poll", file=sys.stderr)
        return 2
    auth = aiohttp.BasicAuth(user, token) if user else None
    print("[loki_tail] %s -> %s  mode=%s query=%s" % (
        base, os.environ.get("LOGNODE_URL", "http://127.0.0.1:9514/loki/api/v1/push"), mode, query))
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, sock_read=120)) as session:
        source = LokiSource(session, base, query, auth=auth, token=None if user else token)
        fwd = Forwarder(session, os.environ.get("LOGNODE_URL", "http://127.0.0.1:9514/loki/api/v1/push"))
        await run(mode, source, fwd,
                  state_file=os.environ.get("LOKI_STATE_FILE", "loki_tail.state"),
                  start_back_s=parse_duration(os.environ.get("LOKI_START", "15m")),
                  poll_s=int(os.environ.get("LOKI_POLL_S", "5")),
                  overlap_s=parse_duration(os.environ.get("LOKI_OVERLAP", "30s"), 30))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
