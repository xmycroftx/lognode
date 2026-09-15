#!/usr/bin/env python3
"""Cluster observed hostile traffic into techniques, and actors into campaigns.

An IP list ages badly: the addresses rotate daily and tell you nothing about
what was attempted. A technique fingerprint does not rotate -- the same tooling
walks the same paths in the same order from whatever address it has today.

Every rule here was written from traffic actually observed against this fleet
(48h of web logs), not from a threat-feed taxonomy. If a pattern is not in the
data it is not in this file, and `unknown` is a real answer rather than a
catch-all that quietly swallows the interesting cases.
"""
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# (technique, tactic, matcher). Order matters: first match wins, so the specific
# techniques precede the general ones and `recon` sits at the bottom.
TECHNIQUES: List[Tuple[str, str, Any]] = [
    # Private keys are their own technique, not a flavour of file harvesting:
    # a stolen .env is a password, a stolen id_rsa is an authorised session.
    ("private-key-theft", "credential-access", re.compile(
        r"/\.ssh/|id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys"
        r"|\.pem$|\.ppk$|\.p12$|\.pfx$|/master\.key|/service-account[^/]*\.json"
        r"|/key\.json|\.tfstate|\.(?:key|crt|cer|keystore|jks)$", re.I)),

    # By far the dominant behaviour observed: environment and credential files,
    # tried under every framework's conventional directory. The no-leading-dot
    # spellings (/env, /env.txt, /config.env) are as common in the data as the
    # dotted ones and were missed by the first version of this rule.
    ("secret-file-harvest", "credential-access", re.compile(
        r"(?:^|/)\.?env(?:$|[./_-])|/\.aws/|secrets?[._-]|credentials"
        r"|wp-config\.php|settings\.py|/config\.py|config\.(?:json|js|php|ya?ml|env)"
        r"|database\.ya?ml|appsettings[^/]*\.json|application\.ya?ml"
        r"|docker-compose\.ya?ml?|\.npmrc|\.htpasswd|/credentials", re.I)),

    # CI definitions leak registry tokens, deploy keys and internal hostnames.
    ("ci-config-exposure", "discovery", re.compile(
        r"Jenkinsfile|\.travis\.ya?ml|\.circleci|\.github/workflows"
        r"|\.drone\.ya?ml|buildspec\.ya?ml|Dockerfile$|/composer\.json"
        r"|/package\.json|/Gemfile", re.I)),

    ("vcs-exposure", "discovery", re.compile(
        r"/\.git(?:/|$)|/\.svn(?:/|$)|/\.hg(?:/|$)|\.gitlab-ci\.ya?ml|/\.gitignore", re.I)),

    # Found in the unclassified tail: /fetch?url=http%3A%2F%2F169.254.169.254
    # The link-local metadata service hands out instance credentials to anything
    # that can make the host fetch a URL, so this outranks almost everything
    # else here -- it is not a probe for a file, it is an attempt at the keys.
    ("ssrf-metadata", "credential-access", re.compile(
        r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data"
        r"|/computeMetadata/|%3A%2F%2F169\.254|\?url=https?(?::|%3A)"
        r"|[?&](?:url|uri|target|dest|redirect|next|proxy)=(?:https?|file|gopher)", re.I)),

    ("rce-attempt", "execution", re.compile(
        r"php://input|allow_url_include|auto_prepend_file|\$\{jndi:|/cgi-bin/"
        r"|eval\(|system\(|/bin/sh|cmd=|shell_exec", re.I)),

    ("path-traversal", "discovery", re.compile(
        r"\.\./|\.\.%2f|%2e%2e|/etc/passwd|/proc/self", re.I)),

    ("webshell-probe", "execution", re.compile(
        r"^/(?:[a-z]{1,3}\.php|shell\.php|cmd\.php|alfa[^/]*\.php|wso\.php"
        r"|up\.php|adminer\.php|backdoor)", re.I)),

    ("info-disclosure", "discovery", re.compile(
        r"phpinfo|/info(?:\.php)?$|/test\.php|server-status|server-info"
        r"|/actuator|/debug|\.DS_Store|phpmyadmin|/telescope|trace\.axd"
        r"|/_profiler|/elmah", re.I)),

    ("api-discovery", "discovery", re.compile(
        r"^/(?:graphql|api(?:$|/)|v[0-9]+/|swagger|openapi|\.well-known/)"
        r"|/api/graphql", re.I)),

    ("cms-probe", "discovery", re.compile(
        r"/wp-(?:admin|login|content|includes|json)|xmlrpc\.php|rest_route"
        r"|/joomla|/drupal|/typo3|/magento", re.I)),

    ("backup-hunt", "credential-access", re.compile(
        r"\.(?:bak|old|save|orig|swp|sql|tar|tar\.gz|zip|7z)(?:$|\?)"
        r"|/backup|/dump", re.I)),

    ("admin-discovery", "discovery", re.compile(
        r"^/(?:admin|administrator|manager|console|dashboard|login|signin)(?:/|$)", re.I)),

    # The long tail defeats enumeration: 509 distinct paths at ~4 hits each, one
    # scanner with a large wordlist. These two rules generalise by SHAPE rather
    # than adding literals, which is why they sit last -- anything a specific
    # rule above recognises keeps its more precise name.
    #
    # Any dotfile request: .env~, .dockerenv, .yarnrc, .htaccess, .vscode/sftp.json.
    ("secret-file-harvest", "credential-access", re.compile(
        r"/\.[A-Za-z0-9_-]+(?:/|~|$|\.[A-Za-z0-9~]+$)", re.I)),

    # Config-shaped basenames with a config-shaped extension.
    ("secret-file-harvest", "credential-access", re.compile(
        r"(?:config|settings|secret|credential|database|parameter|application"
        r"|serverless|firebase|sendgrid|adminsdk|environ|compose|app)"
        r"[^/]*\.(?:json|ya?ml|php|py|rb|js|ini|properties|conf|cfg|env|xml|toml)$", re.I)),

    # Dependency manifests and lockfiles: stack fingerprinting, not credentials.
    ("ci-config-exposure", "discovery", re.compile(
        r"/[^/]*(?:package|composer|yarn|gemfile|pnpm)[^/]*\.(?:json|lock)$"
        r"|\.lock$", re.I)),

    ("recon", "reconnaissance", re.compile(
        r"^/(?:$|\?|robots\.txt|favicon\.ico|sitemap\.xml|index\.html?$)", re.I)),
]

# Paths YOUR application genuinely serves. Hitting these is not an attack, and
# counting them as one inflates every actor that merely used the site.
#
# The default covers only what is generic. Set LOGNODE_BENIGN_PATHS to a regex
# matching your own routes -- without it, every real user of an app with an
# /accounts or /api/v2 route is scored as an actor, and the view fills with
# your own customers.
BENIGN = re.compile(
    os.environ.get("LOGNODE_BENIGN_PATHS",
                   r"^/(?:static/|assets/|health$|healthz$|ping$|status$)"),
    re.I)

# uvicorn/gunicorn access line:  INFO:  1.2.3.4:5678 - "GET /path HTTP/1.1" 404 Not Found
ACCESS_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<sport>\d+)\s+-\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})')


def classify_path(path: str, method: str = "GET") -> Tuple[str, str]:
    """-> (technique, tactic). 'benign' and 'unknown' are both real answers."""
    if not path:
        return ("unknown", "unknown")
    if BENIGN.search(path):
        return ("benign", "none")
    for name, tactic, rx in TECHNIQUES:
        if rx.search(path):
            return (name, tactic)
    return ("unknown", "unknown")


def parse_access(raw: str) -> Optional[Dict[str, str]]:
    m = ACCESS_RE.search(raw or "")
    return m.groupdict() if m else None


def _event_to_hit(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pull (ip, path, method, status) out of an event, however it was stored.

    Prefers the classifier's structured kv when a template has learned the line,
    and falls back to parsing the raw text when it has not -- a template that
    exists today may not have existed when the line arrived.
    """
    kv = ev.get("kv") or {}
    labels = ev.get("labels") or {}
    raw = ev.get("raw") or ""

    ip = kv.get("client_ip") or kv.get("remote_ip") or kv.get("peer_ip") or kv.get("ip")
    path = kv.get("path") or kv.get("url")
    method = kv.get("method") or "GET"
    status = str(kv.get("status") or kv.get("code") or "")

    if not (ip and path):
        parsed = parse_access(raw)
        if not parsed:
            return None
        ip, path = parsed["ip"], parsed["path"]
        method, status = parsed["method"], parsed["status"]

    return {"ip": ip, "path": path, "method": method, "status": status,
            "target": labels.get("instance", "unknown"),
            "ts": ev.get("timestamp")}


def make_internal_check(graph):
    """-> is_internal(ip), true only for addresses a DECLARED node owns.

    The obvious test is wrong and fails open in the dangerous direction:
    resolve_node_id() returns the address UNCHANGED when nothing claims it, so
    "resolved and not external: and not unknown" calls every unrecognised
    address internal. That excluded every real actor and left the threat view
    permanently, silently empty -- it read as "no attacks" rather than "broken".

    Membership in graph.nodes is the only honest test: either the topology
    names this address or it does not.
    """
    def is_internal(ip: str) -> bool:
        try:
            resolved = graph.resolve_node_id(ip)
        except Exception:
            return False
        return (resolved in getattr(graph, "nodes", {})
                and not str(resolved).startswith("external:"))
    return is_internal


def build_threat_view(events: List[Dict[str, Any]],
                      min_hits: int = 1,
                      is_internal=None) -> Dict[str, Any]:
    """Aggregate events into actors, then cluster actors into campaigns.

    `is_internal(ip) -> bool` filters out our own addresses. Pass the graph's
    resolver and anything that folds onto a declared node disappears from the
    threat view. Without it the shared egress NAT shows up as an actor running
    an "admin-discovery" campaign, which is us opening the admin page -- the
    same self-alarm that made our own SSH look like a fleet-wide scan.
    """
    actors: Dict[str, Dict[str, Any]] = {}
    skipped_internal = set()

    for ev in events:
        hit = _event_to_hit(ev)
        if not hit:
            continue
        if is_internal is not None and is_internal(hit["ip"]):
            skipped_internal.add(hit["ip"])
            continue
        technique, tactic = classify_path(hit["path"], hit["method"])
        a = actors.setdefault(hit["ip"], {
            "ip": hit["ip"], "hits": 0, "benign": 0,
            "techniques": defaultdict(int), "tactics": set(),
            "targets": set(), "paths": set(), "statuses": defaultdict(int),
            "first_seen": hit["ts"], "last_seen": hit["ts"],
        })
        a["hits"] += 1
        a["targets"].add(hit["target"])
        a["statuses"][hit["status"]] += 1
        if technique == "benign":
            a["benign"] += 1
        else:
            a["techniques"][technique] += 1
            a["tactics"].add(tactic)
            if len(a["paths"]) < 40:
                a["paths"].add(hit["path"])
        if hit["ts"]:
            a["first_seen"] = min(a["first_seen"] or hit["ts"], hit["ts"])
            a["last_seen"] = max(a["last_seen"] or hit["ts"], hit["ts"])

    out_actors = []
    for a in actors.values():
        hostile = sum(a["techniques"].values())
        if hostile < min_hits:
            continue
        # Cluster on NAMED techniques only. Including "unknown" splits actors
        # running identical tooling apart purely because their unclassified
        # tails differ, which is the opposite of what a fingerprint is for.
        named = sorted(t for t in a["techniques"] if t != "unknown")
        fingerprint = "+".join(named)
        out_actors.append({
            "ip": a["ip"],
            "hits": a["hits"],
            "hostile_hits": hostile,
            "benign_hits": a["benign"],
            "techniques": dict(sorted(a["techniques"].items(),
                                      key=lambda kv: -kv[1])),
            "tactics": sorted(a["tactics"]),
            "fingerprint": fingerprint,
            "targets": sorted(a["targets"]),
            "distinct_paths": len(a["paths"]),
            "sample_paths": sorted(a["paths"])[:8],
            "statuses": dict(a["statuses"]),
            "first_seen": a["first_seen"],
            "last_seen": a["last_seen"],
            "score": _score(a, hostile),
        })

    out_actors.sort(key=lambda x: (-x["score"], -x["hostile_hits"]))

    # Campaigns: actors sharing a technique fingerprint are the same tooling,
    # whatever address it wore today. This is the part an IP list cannot do.
    camps: Dict[str, Dict[str, Any]] = {}
    for a in out_actors:
        fp = a["fingerprint"]
        # "everyone who fetched /" is not a campaign. A campaign needs at least
        # one technique that implies intent beyond loading the front page.
        if not fp or fp in ("recon", "api-discovery", "admin-discovery"):
            continue
        c = camps.setdefault(a["fingerprint"], {
            "fingerprint": a["fingerprint"], "actors": [], "hits": 0,
            "targets": set(), "techniques": a["techniques"].keys(),
        })
        c["actors"].append(a["ip"])
        c["hits"] += a["hostile_hits"]
        c["targets"].update(a["targets"])

    campaigns = sorted(
        ({"fingerprint": c["fingerprint"],
          "actor_count": len(c["actors"]),
          "actors": c["actors"][:25],
          "hits": c["hits"],
          "targets": sorted(c["targets"])} for c in camps.values()),
        key=lambda c: (-c["actor_count"], -c["hits"]))

    technique_totals: Dict[str, int] = defaultdict(int)
    for a in out_actors:
        for t, n in a["techniques"].items():
            technique_totals[t] += n

    return {
        "actors": out_actors,
        "campaigns": campaigns,
        "technique_totals": dict(sorted(technique_totals.items(),
                                        key=lambda kv: -kv[1])),
        "actor_count": len(out_actors),
        "campaign_count": len(campaigns),
        # Named, so it is visible that they were excluded rather than absent.
        "excluded_internal": sorted(skipped_internal),
    }


def _score(a: Dict[str, Any], hostile: int) -> int:
    """Rough severity. Breadth of technique counts for more than volume: one
    address trying four different techniques is more interesting than one
    address fetching .env two hundred times."""
    weights = {
        "ssrf-metadata": 50, "rce-attempt": 40, "webshell-probe": 35,
        "private-key-theft": 30,
        "path-traversal": 25, "secret-file-harvest": 15, "vcs-exposure": 12,
        "ci-config-exposure": 10, "backup-hunt": 10, "cms-probe": 5,
        "admin-discovery": 5, "info-disclosure": 5, "api-discovery": 3,
        "recon": 1,
    }
    score = sum(weights.get(t, 3) for t in a["techniques"])
    score += min(hostile, 50) // 5
    score += 10 * (len(a["targets"]) - 1)      # hitting several hosts is a sweep
    return score
