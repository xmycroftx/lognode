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
from datetime import datetime
from typing import Any, Dict, List, Optional

# uvicorn:  INFO:     1.2.3.4:5678 - "GET /p HTTP/1.1" 404 Not Found
UVICORN_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<sport>\d+)\s+-\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<proto>[\d.]+)"\s+(?P<status>\d{3})')

# nginx combined: 1.2.3.4 - - [date] "GET /p HTTP/1.1" 404 134 "-" "UA string"
NGINX_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[[^\]]+\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<proto>[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+\d+\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"')

# Agents that say what they are. Honesty is not innocence -- zgrab is still a
# scanner -- but an honest scanner and a browser impersonator are different
# problems and should not share a label.
CANDID_UA = re.compile(
    r"zgrab|masscan|nmap|nuclei|sqlmap|dirbuster|gobuster|wpscan|nikto"
    r"|python-requests|curl/|wget|go-http-client|libwww|httpx|scrapy"
    r"|censys|shodan|internetmeasurement|paloaltonetworks|bot\b|spider|crawler",
    re.I)

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


def profile(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """-> {ip: profile}. One pass, grouped by client."""
    by_ip: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"times": [], "ports": set(), "uas": set(), "paths": [],
                 "statuses": [], "protos": set(), "methods": set(),
                 "referers": 0, "assets": 0, "requests": 0})

    for ev in events:
        p = parse_line(ev.get("raw") or "")
        if not p:
            continue
        a = by_ip[p["ip"]]
        a["requests"] += 1
        a["ports"].add(p["sport"] if "sport" in p else None)
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
        t = _ts(ev.get("timestamp"))
        if t:
            a["times"].append(t)

    return {ip: _tells(ip, a) for ip, a in by_ip.items()}


def _tells(ip: str, a: Dict[str, Any]) -> Dict[str, Any]:
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
    if is_candid:
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
    if len(ports) == 1 and a["requests"] >= 10:
        tells.append("all %d requests on ONE connection (port %s) -- keep-alive pipelining"
                     % (a["requests"], next(iter(ports))))

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
        "inconsistency": (_inconsistency(claims_browser, is_candid, got_page, a, rate, worst_404)
                          + (30 if (claims_browser and not is_candid and _anachronistic(uas)) else 0)),
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
