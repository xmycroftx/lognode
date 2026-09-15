# LogNode

Turns unstructured logs into queryable structured events, without you writing
the regexes.

Lines arrive by HTTP, Loki push, or syslog. Known shapes match a compiled regex
immediately. Unknown shapes are clustered by skeleton, and once a cluster has
enough samples a model is asked to write a regex for it. That regex is then
**validated against the samples it was derived from** — if it does not match
them, it is discarded and a deterministic fallback is used instead. Rules that
survive are persisted and become hot-path matches.

The result is a Postgres table where `event` is a name and `kv` is structured
JSONB, so "which process talked to which address" is a query rather than a grep.

---

## Why it might interest you

**The model is not in the hot path.** It runs asynchronously, on clusters, and
anything it produces must pass validation against real lines before it is
trusted. A wrong answer costs a discarded rule, not a wrong field.

**Field names are canonicalised.** `remote_addr`, `client`, `src`, `ipAddress`
and `host` do not stay five different keys. `fields.py` resolves the *type* of a
value and the *role* of its key, so an address becomes `ip` — plus `peer_ip`,
`src_ip`, `remote_ip` where direction matters — whatever the source called it.
That is what makes one query find an address across every log source.

**Searching a value is not searching text.** `?ip=10.0.0.5` matches the
structured field under any key via a GIN index, not a substring match that would
also hit `10.0.0.50`.

**There is a topology graph.** Declare what *should* talk to what; observed
traffic is matched against it. Undeclared peers become `external:<ip>`, declared
links that go quiet are flagged SILENT, and `/graph/subgraph?ip=…` returns the
connected neighbourhood of an address.

**And hostile traffic is clustered by technique, not listed by address.**
Addresses rotate daily; the tooling behind them walks the same paths from
whatever address it has today. `/threats` names what was attempted and groups
actors that attempted the same set.

---

## Quick start

```bash
cp .env.example .env                      # set at least LOGNODE_POSTGRES_DSN
cp topology.example.json topology.json    # optional; omit to declare nothing
python3 server.py
```

Send it something:

```bash
curl -X POST localhost:9514/ingest -H 'Content-Type: text/plain' \
     --data 'sshd[1234]: Accepted publickey for alice from 192.0.2.7 port 54321'
```

Look at it:

```
http://localhost:9514/search      search UI
http://localhost:9514/dashboard   topology
http://localhost:9514/threats     techniques and campaigns
http://localhost:9514/query?ip=192.0.2.7
http://localhost:9514/graph/subgraph?ip=192.0.2.7&depth=1
```

## Query API

| filter | meaning |
|---|---|
| `q=` | raw line contains (trigram-indexed) |
| `ip=` / `value=` | the value under **any** `kv` key, on any host |
| `kv=key:value` | one field, role-pinned — `kv=peer_ip:10.0.0.5` |
| `event=` | event name assigned by the classifier |
| `instance=` | host |
| `since=` | `15m`, `6h`, `7d` |
| `limit=` | max 1000 |

Prefer `ip=` over `kv=ip:…`. The bare `ip` alias holds the *primary* address of
a line, so a connection record is `ip=local` with the far end in `peer_ip`;
`kv=ip:X` silently misses those, `ip=X` does not.

## Model backend

Any chat model that can return JSON. Two wire formats cover almost everything:

```bash
# Ollama
LOGNODE_LLM_URL=http://localhost:11434/api/chat
LOGNODE_LLM_MODEL=qwen2.5-coder:1.5b

# LiteLLM router / vLLM / OpenAI / anything OpenAI-shaped
LOGNODE_LLM_URL=http://localhost:4000/v1/chat/completions
LOGNODE_LLM_MODEL=whatever-the-router-calls-it
LOGNODE_LLM_API_KEY=...
```

The format is inferred from the URL. Reasoning models that leave `content` empty
and answer in `reasoning` / `reasoning_content` are handled on both paths.

## Threat view

`/threats?since=24h` classifies each request into a technique
(`secret-file-harvest`, `private-key-theft`, `ssrf-metadata`, `rce-attempt`,
`path-traversal`, `webshell-probe`, `vcs-exposure`, …), scores each actor, and
clusters actors sharing a technique fingerprint into campaigns. `?format=json`
for the data.

Two settings decide whether it is useful or noise:

```bash
# Your real routes. Without this, every genuine user of an app with an
# /accounts route is scored as an attacker.
LOGNODE_BENIGN_PATHS='^/(?:accounts/|user/|static/|assets/)'
```

and the `is_internal` callable the endpoint passes to `build_threat_view()`,
which is wired to the graph's resolver — anything your declared topology can
name is excluded, and excluded addresses are *reported*, not silently dropped.
Skip that and your own egress NAT shows up as an actor running an
`admin-discovery` campaign, which is you opening your own admin page.

Scoring weights breadth over volume: one address trying four techniques ranks
above one address fetching `.env` two hundred times. The rules were written from
observed traffic and tuned by re-reading what the classifier could not name; the
unclassified share is reported so you can keep doing that on your own data.

### Ownership and behaviour

Actors are enriched with ASN, network, country, registry and reverse DNS, from
Team Cymru's bulk whois — no API key, one TCP connection for the whole batch.
Set `LOGNODE_ENRICH=0` to disable it; note that enriching sends the looked-up
addresses to Cymru, so it is bounded to the actors displayed and cached (misses
included) for `LOGNODE_ENRICH_TTL`.

`behaviour.py` scores the gap between what a client **claims** and what it
**does** — the Cliff Stoll question. A browser that gets a 200 and never fetches
an asset rendered nothing; 114 requests on one keep-alive connection at 14/second
is not reading; a User-Agent claiming a browser build from 2007 has fossilised
because its author copied it once and never looked again.

Deception is scored only where a claim exists to contradict, so `zgrab` and
friends score zero however hostile they are — an honest scanner and a browser
impersonator are different problems. Where no User-Agent is logged at all, the
view says so rather than inferring innocence from absence.

> The User-Agent tells need an access log that records one. uvicorn's default
> format does not; nginx's combined format does. Both dialects are parsed, so
> point it at whichever log has the claim.

## Triage, not alerting

Detections become **findings**: rows with state, not messages in a chat channel.
A finding is raised by a detector, deduplicated by fingerprint, reviewed by an
agent, and then either stays dismissed or does not come back.

```
GET  /findings?state=new       what is waiting
GET  /findings/{id}            full evidence
POST /findings/{id}/verdict    record a judgement
GET  /findings/summary         how much, and how old
```

`mcp_server.py` exposes `list_findings`, `get_finding`, `submit_verdict` and
`triage_summary`, so an MCP-speaking agent can pull the queue, investigate with
`query_logs` and the graph tools, and write back a verdict with its reasoning.

Two properties worth the design:

**A dismissal sticks.** Re-detecting the same subject bumps its occurrence count
and refreshes its evidence — it does not return to the queue. Triage is only
worth doing if the answer persists, and this is the thing an alert channel
fundamentally cannot do.

**Nothing executes anything.** A verdict may *recommend* an action; carrying it
out stays a human decision. An agent that can both judge and act on its own
judgement has no check on it. A rationale is required, and verdicts outside the
known set are refused — a judgement nobody can audit is worse than none.

## Collectors

Optional, and plain enough to read in a sitting:

* `netsnap.py` — a socket snapshot (`ss -tunp`) on a timer, recording which
  process held a connection to which address. A snapshot deliberately, not
  syscall auditing: it misses short-lived connections and costs almost nothing.
* `unitwatch.py` — reports failed systemd units, with a heartbeat every sweep so
  a dead collector is distinguishable from a healthy fleet.

## Requirements

Python 3.11+, PostgreSQL 14+ with `pg_trgm`, and a model endpoint. `asyncpg` and
`aiohttp` are required; `cramjam` speeds up Loki push decoding.

## Tests

```bash
python3 test_graph_subgraph.py   # neighbourhood traversal, dangling edges
python3 test_graph_aging.py      # external-node retirement rules
python3 test_graph_persist.py    # snapshot round-trip
python3 test_llm_backend.py      # both model wire formats, against a mock
python3 test_ttp.py              # technique rules, clustering, self-exclusion
python3 test_behaviour.py        # claim-vs-conduct scoring, and what must NOT fire
```

## Status

Extracted from a working single-fleet deployment, and the shape reflects that:
one collector host, a handful of senders. It has not been run at scale, the
Postgres schema is created on first run and never migrated, and **there is no
authentication in front of the ingest endpoint** — bind it to loopback or a
private interface.

## Licence

MIT.
