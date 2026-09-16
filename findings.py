#!/usr/bin/env python3
"""Findings: detections that are waiting for somebody to decide something.

A Discord message is fire-and-forget. It cannot be queried, it cannot be
dismissed, and it has no idea whether anyone read it -- so the same noise
arrives for ever and you learn to ignore the channel, which is the failure mode
that let a certbot unit fail twice a day for two months in full view.

A finding is a row with state. It is raised once, deduplicated by fingerprint,
reviewed by an agent that writes back a verdict, and then it either stays
dismissed or it does not come back. The dismissal is the point: triage is only
worth doing if the answer persists.

Nothing here executes anything. A verdict may RECOMMEND an action; carrying it
out stays a human decision. An agent that can both judge and act on its own
judgement has no check on it, and tonight alone produced a firewall rule that
silently dropped ICMP and a filter that excluded every attacker -- both of which
looked completely correct from the inside.
"""
import hashlib
import os
import json
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    fingerprint     TEXT UNIQUE NOT NULL,
    kind            TEXT NOT NULL,
    subject         TEXT NOT NULL,
    instance        TEXT,
    severity_hint   TEXT,
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    state           TEXT NOT NULL DEFAULT 'new',
    verdict         TEXT,
    severity        TEXT,
    rationale       TEXT,
    recommended_action TEXT,
    reviewer        TEXT,
    occurrences     INT NOT NULL DEFAULT 1,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    triaged_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings (state, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_kind  ON findings (kind, last_seen DESC);

CREATE TABLE IF NOT EXISTS campaign_actors (
    actor_id        TEXT PRIMARY KEY,
    codename        TEXT NOT NULL,
    emoji           TEXT NOT NULL DEFAULT '',
    fingerprint     TEXT NOT NULL,
    threat_tier     TEXT NOT NULL DEFAULT 'ELEVATED',
    tags            TEXT[] NOT NULL DEFAULT '{}',
    followup_tags   TEXT[] NOT NULL DEFAULT '{}',
    notes           TEXT NOT NULL DEFAULT '',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE campaign_actors ADD COLUMN IF NOT EXISTS emoji TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_campaign_actors_last_seen ON campaign_actors (last_seen DESC);
"""

STATES = ("new", "triaging", "triaged", "dismissed", "actioned")
VERDICTS = ("real", "noise", "known", "needs-action", "false-positive")


def fingerprint(kind: str, subject: str, instance: str = "") -> str:
    """What makes two detections 'the same finding'.

    Deliberately NOT the evidence: the same actor doing the same thing an hour
    later is the same finding with a higher count, not a new one to re-triage.
    """
    raw = "|".join((kind or "", subject or "", instance or ""))
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


async def ensure_schema(pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA)


async def record(pool, kind: str, subject: str, evidence: Dict[str, Any],
                 instance: str = "", severity_hint: str = "medium") -> Dict[str, Any]:
    """Raise a finding, or bump the one that already exists.

    A finding already dismissed stays dismissed -- its occurrence count rises so
    the volume is still visible, but it does not return to the queue. That is
    the whole difference between this and an alert channel.
    """
    fp = fingerprint(kind, subject, instance)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO findings (fingerprint, kind, subject, instance,
                                  severity_hint, evidence)
            VALUES ($1, $2, $3, $4, $5, $6::jsonb)
            ON CONFLICT (fingerprint) DO UPDATE
               SET occurrences = findings.occurrences + 1,
                   last_seen   = NOW(),
                   evidence    = EXCLUDED.evidence,
                   -- only a finding nobody has ruled on re-enters the queue
                   state = CASE WHEN findings.state IN ('dismissed', 'actioned')
                                THEN findings.state ELSE 'new' END
            RETURNING id, fingerprint, state, occurrences
            """,
            fp, kind, subject, instance or None, severity_hint,
            json.dumps(evidence, default=str))
        return dict(row)


async def list_findings(pool, state: Optional[str] = None, kind: Optional[str] = None,
                        limit: int = 50) -> List[Dict[str, Any]]:
    where, params = [], []
    if state:
        params.append(state)
        where.append("state = $%d" % len(params))
    if kind:
        params.append(kind)
        where.append("kind = $%d" % len(params))
    params.append(min(int(limit), 500))
    sql = ("SELECT id, fingerprint, kind, subject, instance, severity_hint, state, "
           "verdict, severity, rationale, recommended_action, reviewer, occurrences, "
           "first_seen, last_seen, triaged_at FROM findings "
           + ("WHERE " + " AND ".join(where) + " " if where else "")
           + "ORDER BY (state = 'new') DESC, last_seen DESC LIMIT $%d" % len(params))
    async with pool.acquire() as conn:
        return [dict(r) for r in await conn.fetch(sql, *params)]


async def get_finding(pool, finding_id: int) -> Optional[Dict[str, Any]]:
    """The full record, evidence included -- what a reviewer needs to judge."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM findings WHERE id = $1", finding_id)
    if not row:
        return None
    d = dict(row)
    if isinstance(d.get("evidence"), str):
        try:
            d["evidence"] = json.loads(d["evidence"])
        except Exception:
            pass
    return d


async def submit_verdict(pool, finding_id: int, verdict: str, rationale: str,
                         reviewer: str, severity: Optional[str] = None,
                         recommended_action: Optional[str] = None) -> Dict[str, Any]:
    """Record a judgement. Never carries it out.

    `recommended_action` is text for a human to read and act on. Nothing in this
    module executes anything, and nothing should be added that does.
    """
    if verdict not in VERDICTS:
        raise ValueError("verdict must be one of %s" % (VERDICTS,))
    if not rationale or len(rationale.strip()) < 10:
        # A verdict without reasoning is unreviewable, and the reasoning is the
        # part a human actually needs when they disagree with it later.
        raise ValueError("rationale is required and must explain the judgement")

    state = "dismissed" if verdict in ("noise", "false-positive", "known") else "triaged"
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE findings
               SET verdict = $2, rationale = $3, reviewer = $4,
                   severity = COALESCE($5, severity, severity_hint),
                   recommended_action = $6, state = $7, triaged_at = NOW()
             WHERE id = $1
            RETURNING id, kind, subject, state, verdict, severity, recommended_action
            """,
            finding_id, verdict, rationale.strip(), reviewer, severity,
            recommended_action, state)
    if not row:
        raise ValueError("no finding with id %s" % finding_id)
    return dict(row)


async def summary(pool) -> Dict[str, Any]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT state, count(*) AS n FROM findings GROUP BY state")
        oldest = await conn.fetchval(
            "SELECT min(first_seen) FROM findings WHERE state = 'new'")
    by_state = {r["state"]: r["n"] for r in rows}
    return {"by_state": by_state,
            "awaiting_triage": by_state.get("new", 0),
            "oldest_untriaged": oldest}


async def list_campaign_actors(pool, limit: int = 100) -> List[Dict[str, Any]]:
    """List persistent campaign actors and their long-term TTP attributions."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT actor_id, codename, emoji, fingerprint, threat_tier,
                   tags, followup_tags, notes, first_seen, last_seen
            FROM campaign_actors
            ORDER BY last_seen DESC
            LIMIT $1
            """, limit)
        res = []
        for r in rows:
            d = dict(r)
            if hasattr(d.get("first_seen"), "isoformat"):
                d["first_seen"] = d["first_seen"].isoformat()
            if hasattr(d.get("last_seen"), "isoformat"):
                d["last_seen"] = d["last_seen"].isoformat()
            res.append(d)
        return res


async def tag_campaign_actor(pool, actor_id: str, followup_tags: List[str],
                             notes: Optional[str] = None, codename: Optional[str] = None,
                             emoji: Optional[str] = None,
                             fingerprint: Optional[str] = None, threat_tier: Optional[str] = None,
                             tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """Assign follow-up tags and investigative notes to a campaign actor."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO campaign_actors (actor_id, codename, emoji, fingerprint, threat_tier, tags, followup_tags, notes)
            VALUES ($1, COALESCE($2, 'UNKNOWN'), COALESCE($3, ''), COALESCE($4, ''), COALESCE($5, 'ELEVATED'),
                    COALESCE($6, '{}'::text[]), $7, COALESCE($8, ''))
            ON CONFLICT (actor_id) DO UPDATE
               SET followup_tags = EXCLUDED.followup_tags,
                   notes         = CASE WHEN EXCLUDED.notes != '' THEN EXCLUDED.notes ELSE campaign_actors.notes END,
                   codename      = CASE WHEN EXCLUDED.codename != 'UNKNOWN' THEN EXCLUDED.codename ELSE campaign_actors.codename END,
                   emoji         = CASE WHEN EXCLUDED.emoji != '' THEN EXCLUDED.emoji ELSE campaign_actors.emoji END,
                   last_seen     = NOW()
            RETURNING actor_id, codename, emoji, fingerprint, threat_tier, tags, followup_tags, notes, first_seen, last_seen
            """,
            actor_id, codename or "UNKNOWN", emoji or "", fingerprint or "", threat_tier or "ELEVATED",
            tags or [], followup_tags, notes or "")
        d = dict(row)
        if hasattr(d.get("first_seen"), "isoformat"):
            d["first_seen"] = d["first_seen"].isoformat()
        if hasattr(d.get("last_seen"), "isoformat"):
            d["last_seen"] = d["last_seen"].isoformat()
        return d


# --- escalation policy -----------------------------------------------------
#
# What is worth a human at all. Deliberately narrow: a queue that collects every
# scanner is an alert channel with extra steps, and the point of this one is
# that somebody actually reads it.

# Worth a human on a SINGLE occurrence -- each is an attempt at credentials or
# execution, and once is enough to want to know.
ESCALATE_ON = ("ssrf-metadata", "rce-attempt", "private-key-theft")

# Worth a human only in QUANTITY. These are enumeration: one /wp-login.php or
# one /8.php is the background radiation of the internet. Raising a finding for
# a single hit teaches you to skim, which is the failure this queue exists to
# avoid -- and it happened, twice, before this threshold existed.
ESCALATE_ON_REPEAT = ("webshell-probe", "cms-probe", "appliance-probe")

REPEAT_THRESHOLD = int(os.environ.get("LOGNODE_FINDING_REPEAT", "3"))
SCORE_FLOOR = int(os.environ.get("LOGNODE_FINDING_SCORE", "40"))
DECEPTION_FLOOR = int(os.environ.get("LOGNODE_FINDING_DECEPTION", "40"))

# How often the sweep looks for new actors worth raising.
#
# This constant lived in server.py and was deleted by accident when the policy
# above was moved here -- the edit removed a contiguous range that happened to
# contain it. Nothing caught that: it is referenced exactly once, inside the
# sweep loop, so the module imported fine, the task started, did one pass, and
# died with a NameError that only appeared in the journal. The triage queue was
# silently not running for a day. It lives with the policy it paces now, where
# deleting one and keeping the other is harder to do without noticing.
SWEEP_SECONDS = int(os.environ.get("LOGNODE_FINDING_SWEEP", "300"))


def should_raise(actor: Dict[str, Any]) -> str:
    """-> reason to raise a finding, or '' to leave the actor alone."""
    techniques = actor.get("techniques") or {}

    hit = [t for t in ESCALATE_ON if t in techniques]
    if hit:
        return "attempted " + ", ".join(hit)

    repeat = [t for t in ESCALATE_ON_REPEAT
              if techniques.get(t, 0) >= REPEAT_THRESHOLD]
    if repeat:
        return "repeated %s" % ", ".join(
            "%s x%d" % (t, techniques[t]) for t in repeat)

    if (actor.get("inconsistency") or 0) >= DECEPTION_FLOOR:
        return "claimed to be something it is not (inconsistency %d)" % actor["inconsistency"]

    if (actor.get("score") or 0) >= SCORE_FLOOR:
        return "breadth of technique (score %d)" % actor["score"]

    return ""
