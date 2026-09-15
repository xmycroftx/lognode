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
```

## Status

Extracted from a working single-fleet deployment, and the shape reflects that:
one collector host, a handful of senders. It has not been run at scale, the
Postgres schema is created on first run and never migrated, and **there is no
authentication in front of the ingest endpoint** — bind it to loopback or a
private interface.

## Licence

MIT.
