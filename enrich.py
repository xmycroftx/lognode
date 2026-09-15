#!/usr/bin/env python3
"""Who owns an address: ASN, network, country, and reverse DNS.

An address alone is not evidence. "198.51.100.7 tried 42 private-key paths" is a
line in a log; "an address in a cloud provider's range, allocated last year,
tried 42 private-key paths" is a sentence about a rented VM, and "nine addresses
in one /19 ran the identical technique set" is a sentence about one operator.
Ownership is what turns actors into attribution.

Backend is Team Cymru's bulk whois over TCP 43: no API key, no HTTP, one
connection for the whole batch, and it answers ASN, prefix, country, registry
and allocation date together. Reverse DNS comes from the local resolver.

  NOTE: enriching sends the addresses being looked up to Team Cymru. They are
  adversary addresses rather than user data, and Cymru is the service this
  industry already uses for exactly this, but it IS an external disclosure --
  so it is off unless asked for, bounded to the actors actually displayed, and
  cached so the same address is not re-sent on every page load.
"""
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Optional

CYMRU_HOST = os.environ.get("LOGNODE_WHOIS_HOST", "whois.cymru.com")
CYMRU_PORT = int(os.environ.get("LOGNODE_WHOIS_PORT", "43"))
TIMEOUT = float(os.environ.get("LOGNODE_ENRICH_TIMEOUT", "8"))
TTL = int(os.environ.get("LOGNODE_ENRICH_TTL", str(24 * 3600)))
MAX_LOOKUPS = int(os.environ.get("LOGNODE_ENRICH_MAX", "200"))

# ip -> (fetched_at, record)
_cache: Dict[str, Any] = {}


def _fresh(ip: str) -> Optional[Dict[str, Any]]:
    hit = _cache.get(ip)
    if not hit:
        return None
    at, rec = hit
    return rec if (time.time() - at) < TTL else None


def bulk_asn(ips: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """-> {ip: {asn, prefix, country, registry, allocated, org}}

    One connection for the whole list. A failure returns what is already
    cached rather than raising: enrichment is a nicety, and a threat view that
    disappears because a whois server is down is worse than an unenriched one.
    """
    want = [ip for ip in dict.fromkeys(ips) if _fresh(ip) is None][:MAX_LOOKUPS]
    out = {ip: _fresh(ip) for ip in ips if _fresh(ip) is not None}
    if not want:
        return out

    query = "begin\nverbose\n" + "\n".join(want) + "\nend\n"
    try:
        sock = socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        sock.sendall(query.encode())
        chunks = []
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        body = b"".join(chunks).decode(errors="replace")
    except Exception as exc:
        print("[Enrich] whois lookup failed (%s: %s) -- returning uneriched"
              % (type(exc).__name__, exc))
        return out

    now = time.time()
    for line in body.splitlines():
        if "|" not in line or line.lower().startswith("bulk mode"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip, prefix, country, registry, allocated, org = parts[:7]
        rec = {"asn": asn if asn and asn != "NA" else None,
               "prefix": prefix or None,
               "country": country or None,
               "registry": registry or None,
               "allocated": allocated or None,
               "org": org or None}
        _cache[ip] = (now, rec)
        out[ip] = rec

    # Addresses the service knew nothing about are cached as empty too, so a
    # dark corner of the internet is not re-queried on every refresh.
    for ip in want:
        if ip not in out:
            _cache[ip] = (now, {})
            out[ip] = {}
    return out


# ip -> (fetched_at, hostname or None). Separate from the ASN cache because a
# miss is the common case and must be cached too: most scanner addresses have no
# PTR, and an uncached miss costs a full resolver timeout on every page load.
# Leaving this out made a "cached" second pass take 2.7s instead of 0.003s.
_rdns_cache: Dict[str, Any] = {}


def reverse_dns(ips: Iterable[str], workers: int = 16) -> Dict[str, Optional[str]]:
    """PTR records, in parallel. Most scanner addresses have none."""
    ips = [ip for ip in dict.fromkeys(ips)][:MAX_LOOKUPS]
    now = time.time()
    out: Dict[str, Optional[str]] = {}
    todo = []
    for ip in ips:
        hit = _rdns_cache.get(ip)
        if hit and (now - hit[0]) < TTL:
            out[ip] = hit[1]
        else:
            todo.append(ip)
    if not todo:
        return out

    def one(ip: str):
        try:
            socket.setdefaulttimeout(TIMEOUT / 2)
            return ip, socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip, None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, name in pool.map(one, todo):
            _rdns_cache[ip] = (now, name)
            out[ip] = name
    return out


def enrich_actors(actors: List[Dict[str, Any]], do_rdns: bool = True) -> None:
    """Attach ownership to each actor, in place."""
    ips = [a["ip"] for a in actors]
    asn = bulk_asn(ips)
    rdns = reverse_dns(ips) if do_rdns else {}
    for a in actors:
        rec = asn.get(a["ip"]) or {}
        a["asn"] = rec.get("asn")
        a["org"] = rec.get("org")
        a["country"] = rec.get("country")
        a["prefix"] = rec.get("prefix")
        a["registry"] = rec.get("registry")
        a["allocated"] = rec.get("allocated")
        a["rdns"] = rdns.get(a["ip"])


def group_by_owner(actors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Actors grouped by the network that owns them.

    Complements the technique fingerprint rather than repeating it: a
    fingerprint says two addresses run the same tooling, a shared prefix says
    they are the same rented range. Both together is an operator.
    """
    groups: Dict[str, Dict[str, Any]] = {}
    for a in actors:
        key = a.get("asn") or "unknown"
        g = groups.setdefault(key, {
            "asn": a.get("asn"), "org": a.get("org"), "country": a.get("country"),
            "actors": [], "hits": 0, "prefixes": set(), "techniques": set(),
        })
        g["actors"].append(a["ip"])
        g["hits"] += a.get("hostile_hits", 0)
        if a.get("prefix"):
            g["prefixes"].add(a["prefix"])
        g["techniques"].update(a.get("techniques") or {})

    out = [{"asn": g["asn"], "org": g["org"], "country": g["country"],
            "actor_count": len(g["actors"]), "actors": g["actors"][:25],
            "hits": g["hits"], "prefixes": sorted(g["prefixes"])[:6],
            "techniques": sorted(g["techniques"])}
           for g in groups.values()]
    out.sort(key=lambda g: (-g["actor_count"], -g["hits"]))
    return out
