#!/usr/bin/env python3
"""The log_events table, and what removes rows from it.

Both halves of a storage lifecycle live here on purpose. Until this file the
DDL for the core table existed nowhere in the repository -- it had been applied
by hand and survived only inside the running database and its rsync copy -- and
nothing anywhere ever deleted a row. Neither of those is a problem at eleven
hosts. At ninety-two, on a database that lives in RAM, the second one is what
takes the service down, and the first one is why it could not then be rebuilt.
"""
import asyncio
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# The verified live definition: seven columns, eight indexes, one extension.
# Every statement is IF NOT EXISTS so that running this against a database
# whose schema was applied out of band is a no-op. No ALTER, no DROP, no
# reconciliation: if a live table differs from this, that is for a person.
SCHEMA = """
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS log_events (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    event       TEXT NOT NULL,
    labels      JSONB DEFAULT '{}'::jsonb,
    kv          JSONB NOT NULL,
    latency_us  DOUBLE PRECISION,
    raw         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp     ON log_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_event         ON log_events (event);
CREATE INDEX IF NOT EXISTS idx_events_event_time    ON log_events (event, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_instance_time ON log_events ((labels->>'instance'), timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_labels        ON log_events USING gin (labels);
CREATE INDEX IF NOT EXISTS idx_events_kv            ON log_events USING gin (kv);
CREATE INDEX IF NOT EXISTS idx_events_raw_trgm      ON log_events USING gin (raw gin_trgm_ops);
"""

SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"


async def ensure_schema(pool) -> None:
    """Apply SCHEMA. Safe on an existing database; see the note above."""
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA)


# --- retention ---------------------------------------------------------------
#
# Off unless LOGNODE_RETENTION is set. For a public repository that is the only
# defensible default: an upgrade must not start deleting a stranger's data.
#
# Arithmetic for the reader deciding a value: at ~612 bytes per row all-in
# (heap plus eight indexes), 92 hosts at this fleet's per-host rate produce
# roughly 675 MB a day. A 24 GB RAM disk with 2.4 GB used fills in about 33
# days with no retention at all.

MIN_RETENTION_S = 3600
_UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
_SPEC = re.compile(r"^\s*(\d+)\s*([mhdw])\s*$", re.I)


def retention_window(spec: Optional[str]) -> Optional[int]:
    """'7d' / '48h' / '90m' / '2w' -> seconds. None, '', '0', 'off' -> None.

    Raises ValueError below MIN_RETENTION_S and on a unitless number.

    This is the most destructive setting in the codebase, and its failure mode
    is a typo. '7' meaning weeks but read as days deletes six sevenths of the
    table; '1m' typed for one month deletes all of it. So a unitless number is
    refused rather than guessed, and the floor makes the one-minute typo
    impossible to express.
    """
    if spec is None:
        return None
    s = str(spec).strip().lower()
    if s in ("", "0", "off", "none", "false", "never"):
        return None
    m = _SPEC.match(s)
    if not m:
        raise ValueError(
            "LOGNODE_RETENTION=%r: give a number with a unit (m, h, d, w), "
            "e.g. 14d -- a unitless number is ambiguous and refused" % spec)
    seconds = int(m.group(1)) * _UNITS[m.group(2)]
    if seconds < MIN_RETENTION_S:
        raise ValueError(
            "LOGNODE_RETENTION=%r is under the %d-second floor" % (spec, MIN_RETENTION_S))
    return seconds


def retention_sql(batch_rows: int = 20000) -> str:
    """One bounded DELETE. The window is always $1, never interpolated.

    Batched by ctid so a single statement never holds a long transaction
    against eight indexes; the caller loops until a batch removes nothing. The
    inner select orders on the timestamp index, so each batch is an index
    range scan rather than a heap walk.
    """
    batch_rows = int(batch_rows)
    if batch_rows < 1:
        raise ValueError("batch_rows must be positive")
    return (
        "DELETE FROM log_events WHERE ctid = ANY(ARRAY("
        "SELECT ctid FROM log_events "
        "WHERE timestamp < now() - ($1::double precision * interval '1 second') "
        "ORDER BY timestamp LIMIT %d))" % batch_rows)


def _rows_deleted(status: str) -> int:
    # asyncpg returns the command tag, e.g. "DELETE 20000".
    try:
        return int(str(status).rsplit(" ", 1)[-1])
    except (ValueError, IndexError):
        return 0


async def sweep_once(pool, window_s: int, batch_rows: int = 20000,
                     pause_s: float = 0.2, max_batches: int = 500) -> int:
    """Delete everything older than window_s, in batches. -> rows deleted.

    max_batches bounds one sweep so a first run against a table that has never
    been pruned does not monopolise the connection for an hour; the remainder
    goes on the next sweep.
    """
    sql = retention_sql(batch_rows)
    total = 0
    async with pool.acquire() as conn:
        for _ in range(max_batches):
            n = _rows_deleted(await conn.execute(sql, float(window_s)))
            total += n
            if n < batch_rows:
                break
            await asyncio.sleep(pause_s)
    return total


async def retention_loop(pool_of: Callable[[], Any], stats: Dict[str, Any],
                         window_s: int, sweep_s: int = 600,
                         batch_rows: int = 20000) -> None:
    """Background task: sweep every sweep_s seconds while a pool exists."""
    stats.setdefault("retention_deleted_total", 0)
    stats["retention_window_s"] = window_s
    await asyncio.sleep(60)          # let ingest and the schema settle first
    while True:
        try:
            pool = pool_of()
            if pool is not None:
                t0 = time.time()
                n = await sweep_once(pool, window_s, batch_rows)
                stats["retention_deleted_total"] += n
                stats["retention_last_run"] = t0
                stats["retention_last_deleted"] = n
                if n:
                    print("[Retention] removed %d rows older than %ds in %.1fs"
                          % (n, window_s, time.time() - t0))
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print("[Retention] sweep error: %s" % exc)
        await asyncio.sleep(sweep_s)


def configured_window() -> Optional[int]:
    """The window from the environment, or None. Raises on a bad value, on
    purpose: a misconfigured destructive setting should stop startup, not be
    silently ignored until someone notices the disk."""
    return retention_window(os.environ.get("LOGNODE_RETENTION"))
