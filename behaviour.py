#!/usr/bin/env python3
"""Does the client behave like the thing it claims to be?

Cliff Stoll caught his intruder on a mismatch, not a signature: the account
belonged to someone who would never have typed `ps -eafg`. The useful question
is never "is this string on a blocklist", it is "is this consistent".

So this module scores the gap between what a client CLAIMS -- its User-Agent, a
browser's implied behaviour -- and what it DOES. A browser that fetches a page
and never asks for the favicon did not render anything. A visitor that walks 113
paths on one keep-alive connection at four per second is not reading. An agent
calling itself Chrome that does both is lying, and the lie is worth more than
any individual request, because it survives the address changing.

Every tell here was derived from traffic observed against a live host, and each
one records what it is inferring rather than asserting a verdict.
"""
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# uvicorn:  INFO:     1.2.3.4:5678 - "GET /p HTTP/1.1" 404 Not Found
UVICORN_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<sport>\d+)\s+-\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<proto>[\d.]+)"\s+(?P<status>\d{3})')

# nginx combined: 1.2.3.4 - - [date] "GET /p HTTP/1.1" 404 134 "-" "UA string"
NGINX_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<when>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<proto>[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+\d+\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"')

_MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
_CLF = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?")


def clf_time(when: str):
    """'15/Sep/2026:06:04:42 +0000' -> epoch seconds, or None."""
    m = _CLF.search(when or "")
    if not m:
        return None
    day, mon, year, hh, mm, ss, off = m.groups()
    if mon not in _MONTHS:
        return None
    try:
        t = datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                     tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    if off:
        sign = 1 if off[0] == "+" else -1
        t -= sign * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)
    return t

# Agents that say what they are. Honesty is not innocence -- zgrab is still a
# scanner -- but an honest scanner and a browser impersonator are different
# problems and should not share a label.
CANDID_UA = re.compile(
    r"zgrab|masscan|nmap|nuclei|sqlmap|dirbuster|gobuster|wpscan|nikto"
    r"|python-requests|curl/|wget|go-http-client|libwww|httpx|scrapy"
    r"|censys|shodan|internetmeasurement|paloaltonetworks|spider|crawler|bot\b",
    re.I)

# Crawlers whose identity can be CHECKED, and the domains their addresses must
# reverse-resolve into. Each operator documents this themselves; it is the
# standard verification and it is why claiming one of these is a risk for an
# impostor rather than free cover.
VERIFIABLE_CRAWLERS = {
    "googlebot":           (".googlebot.com", ".google.com"),
    "google-inspectiontool": (".googlebot.com", ".google.com"),
    "storebot-google":     (".googlebot.com", ".google.com"),
    "bingbot":             (".search.msn.com",),
    "adidxbot":            (".search.msn.com",),
    "duckduckbot":         (".duckduckgo.com",),
    "yandexbot":           (".yandex.ru", ".yandex.net", ".yandex.com"),
    "baiduspider":         (".baidu.com", ".baidu.jp"),
    "applebot":            (".applebot.apple.com", ".apple.com"),
    "facebookexternalhit": (".fbsv.net", ".facebook.com"),
    "petalbot":            (".petalsearch.com", ".aspiegel.com"),
}


def crawler_claim(ua: str):
    """-> the verifiable crawler this UA claims to be, or None."""
    low = (ua or "").lower()
    for name in VERIFIABLE_CRAWLERS:
        if name in low:
            return name
    return None


def crawler_verdict(name: str, rdns):
    """-> (ok, explanation).

    ok is True (verified), False (contradicted) or None (cannot tell).
    An ABSENT PTR is a failure, not an unknown: every operator in the table
    above publishes reverse DNS for its crawlers precisely so this check works.
    """
    suffixes = VERIFIABLE_CRAWLERS.get(name) or ()
    if not rdns:
        return False, ("claims %s but the address has no reverse DNS -- every "
                       "real one publishes it so this check can be made" % name)
    host = str(rdns).lower().rstrip(".")
    if any(host.endswith(sfx) for sfx in suffixes):
        return True, ""
    return False, ("claims %s but reverse DNS is %s, which is not %s"
                   % (name, host, " or ".join(s.lstrip(".") for s in suffixes)))

BROWSER_UA = re.compile(r"Mozilla/5\.0.*(?:Chrome/|Firefox/|Safari/|Edg/)", re.I)

# Versions no living user is still running. Scanner authors copy a UA once and
# never revisit it, so the string fossilises while real browsers roll forward
# every few weeks. This is the purest form of the tell: not that the claim is on
# a list, but that nobody could still be making it honestly. Observed in live
# traffic: "Firefox/1.5.0.9" on Linux i686, a 2007 build, driving 14 requests a
# second in 2026.
ANACHRONISTIC = [
    (re.compile(r"Firefox/(\d+)", re.I), 115, "Firefox"),
    (re.compile(r"Chrome/(\d+)", re.I), 110, "Chrome"),
    (re.compile(r"Edg(?:e)?/(\d+)", re.I), 110, "Edge"),
]
ANCIENT_MARKERS = re.compile(
    r"MSIE [1-9]\b|Windows NT [45]\.|Windows 9[58]|Mac OS X 10_[0-9]\b"
    r"|Trident/|Netscape|Linux i686.*rv:1\.", re.I)


def ua_anachronism(ua: str):
    """-> reason, or None. Conservative: only flags what is unambiguous."""
    if not ua:
        return None
    for rx, floor, name in ANACHRONISTIC:
        m = rx.search(ua)
        if m:
            try:
                ver = int(m.group(1))
            except ValueError:
                continue
            if ver < floor:
                return "claims %s %d, a build no current user runs" % (name, ver)
    if ANCIENT_MARKERS.search(ua):
        return "claims a platform or engine that is long out of service"
    return None


# What a real browser fetches without being asked, having rendered a page.
ASSET_RE = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|woff2?|ico)(?:$|\?)|/favicon\.ico", re.I)


def from_fields(kv: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """An access record that is ALREADY structured -> parse_line's shape.

    A row that arrived from a Logstash pipeline (or matched a template that
    captured these fields) does not need its text re-parsed with a regex. This
    is the seam that lets the deception scoring read grok's output directly.

    Requires ip AND path AND status together. Anything less falls through to the
    regexes, because a half-filled dict is worse than no dict here: profile()
    would build an actor out of absences -- no user agent, no referer, no assets
    fetched -- which is the exact signature it scores as maximum deception. A
    partial parse would manufacture attackers out of non-HTTP log lines.
    """
    if not kv:
        return None
    ip = kv.get("ip") or kv.get("client_ip") or kv.get("remote_ip")
    path = kv.get("path") or kv.get("url")
    status = kv.get("status") or kv.get("code")
    if not (ip and path and status is not None):
        return None
    return {
        "ip": str(ip),
        # None on purpose: clf_time() only understands nginx's bracketed format,
        # so this sends profile() to its fallback, which reads the row's own
        # timestamp column -- and that column now holds the event's real time
        # rather than ingest time.
        "when": None,
        "method": (str(kv.get("method")) if kv.get("method") else None),
        "path": str(path),
        "proto": (str(kv.get("proto")) if kv.get("proto") else None),
        # str(), because _tells compares `s == "404"` with no coercion and a
        # structured source may well carry this as an integer.
        "status": str(status),
        "referer": (str(kv.get("referer")) if kv.get("referer") else None),
        "ua": (str(kv.get("ua")) if kv.get("ua") else None),
        "sport": (str(kv.get("sport")) if kv.get("sport") else None),
        "source": "structured",
    }


def parse_line(raw: str) -> Optional[Dict[str, Any]]:
    """Either access-log dialect -> a common shape. UA only where it exists."""
    m = NGINX_RE.search(raw or "")
    if m:
        d = m.groupdict()
        d["source"] = "nginx"
        return d
    m = UVICORN_RE.search(raw or "")
    if m:
        d = m.groupdict()
        d.update(ua=None, referer=None, source="uvicorn")
        return d
    return None


def _ts(value) -> Optional[float]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def profile(events: List[Dict[str, Any]],
            rdns: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """-> {ip: profile}. One pass, grouped by client.

    `rdns` maps ip -> hostname (or None). Supply it and crawler claims are
    verified rather than believed; omit it and they are reported as
    unverified rather than silently trusted.
    """
    by_ip: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"times": [], "ports": set(), "uas": set(), "paths": [],
                 "statuses": [], "protos": set(), "methods": set(),
                 "referers": 0, "assets": 0, "requests": 0, "port_seen": 0})

    for ev in events:
        # Structure the shipper already derived beats re-deriving it with a
        # regex, and is the only way an ECS row is readable at all -- its
        # raw may be a bare message with no access-log syntax in it.
        p = from_fields(ev.get("kv")) or parse_line(ev.get("raw") or "")
        if not p:
            continue
        a = by_ip[p["ip"]]
        a["requests"] += 1
        # nginx's combined format has no source port; uvicorn's line does. Track
        # how many requests actually carried one, so the keep-alive tell below
        # describes the observations it is based on rather than the whole actor.
        if p.get("sport"):
            a["ports"].add(p["sport"])
            a["port_seen"] = a.get("port_seen", 0) + 1
        a["protos"].add(p.get("proto"))
        a["methods"].add(p.get("method"))
        a["paths"].append(p["path"])
        a["statuses"].append(p["status"])
        if p.get("ua"):
            a["uas"].add(p["ua"])
        if p.get("referer") and p["referer"] not in ("-", ""):
            a["referers"] += 1
        if ASSET_RE.search(p["path"]):
            a["assets"] += 1
        # The log line's OWN clock beats the ingest clock. A backfill or a
        # batched shipment arrives with hundreds of identical ingest
        # timestamps, which would read as a single enormous burst and invent
        # cadence tells that never happened.
        t = clf_time(p.get("when")) or _ts(ev.get("timestamp"))
        if t:
            a["times"].append(t)

    rdns = rdns or {}
    return {ip: _tells(ip, a, rdns.get(ip)) for ip, a in by_ip.items()}


def _tells(ip: str, a: Dict[str, Any], rdns=None) -> Dict[str, Any]:
    times = sorted(a["times"])
    span = (times[-1] - times[0]) if len(times) > 1 else 0.0
    rate = (len(times) / span) if span > 0 else 0.0

    gaps = [round(times[i + 1] - times[i], 3) for i in range(len(times) - 1)]
    median_gap = sorted(gaps)[len(gaps) // 2] if gaps else None

    # longest run of consecutive 404s: a person stops, a wordlist does not
    worst_404 = run = 0
    for s in a["statuses"]:
        run = run + 1 if s == "404" else 0
        worst_404 = max(worst_404, run)

    uas = sorted(a["uas"])
    claims_browser = any(BROWSER_UA.search(u) for u in uas)
    is_candid = any(CANDID_UA.search(u) for u in uas)
    got_page = any(s in ("200", "304") for s in a["statuses"])

    tells: List[str] = []

    # --- the central one: claim versus conduct ---
    if claims_browser and not is_candid:
        if got_page and a["assets"] == 0:
            tells.append("claims a browser but never fetched an asset after a 200 "
                         "-- nothing was rendered")
        if a["requests"] > 5 and a["referers"] == 0:
            tells.append("claims a browser but sent no Referer on any request")
    for u in uas:
        reason = ua_anachronism(u)
        if reason and not is_candid:
            tells.append(reason)
            break
    # A verifiable crawler claim is checked, not taken at face value.
    claimed_crawler = next((c for c in (crawler_claim(u) for u in uas) if c), None)
    crawler_ok = None
    if claimed_crawler:
        crawler_ok, why = crawler_verdict(claimed_crawler, rdns)
        if crawler_ok is False:
            tells.append(why)
        elif crawler_ok is True:
            tells.append("verified %s (reverse DNS confirms)" % claimed_crawler)

    if is_candid and not claimed_crawler:
        tells.append("identifies itself as tooling (%s)" % uas[0][:60])
    if len(uas) > 1:
        tells.append("presented %d different User-Agents from one address" % len(uas))
    if not uas and a["requests"] > 20:
        tells.append("no User-Agent recorded on this port -- see nginx for the claim")

    # --- cadence ---
    if rate >= 2:
        tells.append("%.1f requests/second sustained over %.0fs -- scripted" % (rate, span))
    if median_gap is not None and median_gap <= 0.25 and len(gaps) >= 8:
        tells.append("median gap %.2fs between requests -- no human read anything" % median_gap)

    # --- connection reuse ---
    ports = {p for p in a["ports"] if p}
    port_seen = a.get("port_seen", 0)
    if len(ports) == 1 and port_seen >= 10:
        qualifier = ("all %d requests" % port_seen if port_seen == a["requests"]
                     else "%d of %d requests" % (port_seen, a["requests"]))
        tells.append("%s on ONE connection (port %s) -- keep-alive pipelining"
                     % (qualifier, next(iter(ports))))

    # --- persistence past failure ---
    if worst_404 >= 20:
        tells.append("%d consecutive 404s without stopping -- walking a wordlist" % worst_404)

    if "HTTP/1.0" in {"HTTP/" + p for p in a["protos"] if p}:
        tells.append("HTTP/1.0 -- older than any current browser")

    return {
        "ip": ip,
        "requests": a["requests"],
        "span_seconds": round(span, 1),
        "peak_rate_per_s": round(rate, 2),
        "median_gap_s": median_gap,
        "connections": len(ports) or None,
        "user_agents": uas,
        "claims_browser": claims_browser,
        "self_identified_tool": is_candid,
        "asset_fetches": a["assets"],
        "referers": a["referers"],
        "longest_404_run": worst_404,
        "methods": sorted(m for m in a["methods"] if m),
        "tells": tells,
        # Deception is the claim NOT matching the conduct. An honest scanner
        # scores zero here however hostile it is -- that is the point.
        "claimed_crawler": claimed_crawler,
        "crawler_verified": crawler_ok,
        "inconsistency": (_inconsistency(claims_browser, is_candid, got_page, a, rate, worst_404)
                          + (30 if (claims_browser and not is_candid and _anachronistic(uas)) else 0)
                          # Impersonating a whitelisted crawler outranks every
                          # other tell here: it is a bid for privileged access
                          # and the contradiction is objective, not inferred.
                          + (60 if crawler_ok is False else 0)),
        "anachronistic_ua": bool(uas) and _anachronistic(uas),
    }


def _inconsistency(claims_browser, is_candid, got_page, a, rate, worst_404) -> int:
    if not claims_browser or is_candid:
        return 0
    score = 0
    if got_page and a["assets"] == 0:
        score += 40
    if a["requests"] > 5 and a["referers"] == 0:
        score += 20
    if rate >= 2:
        score += 20
    if worst_404 >= 20:
        score += 20
    return score


def _anachronistic(uas) -> bool:
    return any(ua_anachronism(u) for u in uas)
