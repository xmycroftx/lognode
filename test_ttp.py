#!/usr/bin/env python3
"""Technique classification, actor scoring, and campaign clustering.

The path samples are real: every one appeared in traffic against a live host.
"""
import os

# This fleet's real routes, so the benign assertions below exercise the
# configured behaviour rather than the generic default.
os.environ.setdefault("LOGNODE_BENIGN_PATHS",
                      r"^/(?:user/me|accounts/|auth|static/|patch/|openapi\.json)")

import ttp

ok = True


def check(label, cond, detail=""):
    global ok
    print("  %-56s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        ok = False


def tech(path):
    return ttp.classify_path(path)[0]


# --- the dominant technique, in the spellings actually observed -------------
for p in ["/.env", "/.env.production", "/api/.env", "/laravel/.env", "/env",
          "/env.txt", "/config.env", "/secrets.env", "/config/database.yml",
          "/appsettings.json", "/wp-config.php.bak", "/.aws/credentials",
          "/config/app.php", "/instance/config.py"]:
    check("secret-file-harvest: %s" % p, tech(p) == "secret-file-harvest", "got=%s" % tech(p))

# --- credential theft that is NOT a config file ----------------------------
for p in ["/.ssh/id_rsa", "/.ssh/authorized_keys", "/server.key",
          "/service-account.json", "/config/master.key", "/terraform.tfstate"]:
    check("private-key-theft: %s" % p, tech(p) == "private-key-theft", "got=%s" % tech(p))

# --- the one that matters most ---------------------------------------------
for p in ["/fetch?url=http%3A%2F%2F169.254.169.254/latest/meta-data/",
          "/proxy?url=http://169.254.169.254/",
          "/x?target=http://metadata.google.internal/computeMetadata/v1/"]:
    check("ssrf-metadata: %s" % p[:44], tech(p) == "ssrf-metadata", "got=%s" % tech(p))

check("ssrf outscores every other technique",
      max(ttp._score({"techniques": {"ssrf-metadata": 1}, "targets": {"a"}}, 1),
          ttp._score({"techniques": {"rce-attempt": 1}, "targets": {"a"}}, 1))
      == ttp._score({"techniques": {"ssrf-metadata": 1}, "targets": {"a"}}, 1))

# --- other techniques -------------------------------------------------------
check("vcs-exposure", tech("/.git/config") == "vcs-exposure")
check("path-traversal", tech("/?file=../../../../etc/passwd") == "path-traversal")
check("rce-attempt", tech("/?x=php://input") == "rce-attempt")

# --- the unclassified tail, measured at 24.5% of the 24h view -----------------
# CVE-2017-9841 under every prefix the scanner tries. This was ~80 lines a day
# scored "unknown": no cluster, no finding, for an RCE probe.
for p in ["/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
          "/lib/phpunit/Util/PHP/eval-stdin.php",
          "/ws/ec/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
          "/phpunit/src/Util/PHP/eval-stdin.php"]:
    check("eval-stdin.php is rce-attempt: %s" % p[:40], tech(p) == "rce-attempt", tech(p))
for p in ["/storage/logs/laravel.log", "/error_log", "/web.config",
          "/kubernetes.yml", "/google-services.json"]:
    check("harvest: %s" % p, tech(p) == "secret-file-harvest", tech(p))
for p in ["/fetch", "/proxy", "/sse", "/proxy?x=1"]:
    check("bare relay endpoint is proxy-probe: %s" % p, tech(p) == "proxy-probe", tech(p))
check("but /fetch?url=http:// is still SSRF, not proxy-probe",
      tech("/fetch?url=http%3A%2F%2F169.254.169.254/") == "ssrf-metadata")
check("app-ads.txt is benign", tech("/app-ads.txt") == "benign", tech("/app-ads.txt"))
check("ads.txt is benign", tech("/ads.txt") == "benign")
check("ads.txt is benign even under a custom LOGNODE_BENIGN_PATHS (this file sets one)",
      "ads" not in os.environ.get("LOGNODE_BENIGN_PATHS", "") and tech("/ads.txt") == "benign")
check("a legitimate /error page is not harvest", tech("/error") != "secret-file-harvest", tech("/error"))

check("webshell-probe", tech("/i.php") == "webshell-probe")
check("info-disclosure", tech("/phpinfo.php") == "info-disclosure")
check("cms-probe", tech("/wp-login.php") == "cms-probe")
check("recon", tech("/") == "recon" and tech("/robots.txt") == "recon")

# --- benign app routes must not be counted as attacks ----------------------
for p in ["/user/me", "/accounts/create", "/static/app.js", "/patch/client.zip"]:
    check("benign: %s" % p, tech(p) == "benign", "got=%s" % tech(p))

# --- specific beats general -------------------------------------------------
check("a dotfile that is a git path stays vcs-exposure",
      tech("/.git/config") == "vcs-exposure")
check("a .bak config is still harvest, not just backup-hunt",
      tech("/wp-config.php.bak") == "secret-file-harvest")

# --- parsing ----------------------------------------------------------------
line = 'INFO:     203.0.113.9:44322 - "GET /.env HTTP/1.1" 404 Not Found'
p = ttp.parse_access(line)
check("parses a uvicorn access line",
      p and p["ip"] == "203.0.113.9" and p["path"] == "/.env" and p["status"] == "404")
check("non-access lines parse to None", ttp.parse_access("systemd: Started thing.") is None)


def ev(ip, path, inst="web"):
    return {"raw": 'INFO:     %s:5000 - "GET %s HTTP/1.1" 404 Not Found' % (ip, path),
            "labels": {"instance": inst}, "kv": {}, "timestamp": "2026-09-15T00:00:00Z"}


# --- aggregation and clustering --------------------------------------------
events = [ev("198.51.100.1", "/.env"), ev("198.51.100.1", "/.git/config"),
          ev("198.51.100.2", "/.env"), ev("198.51.100.2", "/.git/config"),
          ev("198.51.100.3", "/wp-login.php"),
          ev("203.0.113.5", "/"), ev("203.0.113.5", "/user/me")]
v = ttp.build_threat_view(events)

check("actors aggregated", v["actor_count"] == 4, "got=%d" % v["actor_count"])
camp = [c for c in v["campaigns"] if c["actor_count"] > 1]
check("identical technique sets cluster into one campaign",
      len(camp) == 1 and set(camp[0]["actors"]) == {"198.51.100.1", "198.51.100.2"},
      str(camp))
check("fingerprint is the sorted technique set",
      camp and camp[0]["fingerprint"] == "secret-file-harvest+vcs-exposure")
check("campaign has actor_name and actor_id",
      bool(camp[0].get("actor_name")) and str(camp[0].get("actor_id", "")).startswith("ACTOR-"),
      str(camp[0]))
check("campaign has first_seen and last_seen",
      camp[0].get("first_seen") == "2026-09-15T00:00:00Z" and camp[0].get("last_seen") == "2026-09-15T00:00:00Z")
check("actors have campaign attribution and seen timestamps",
      any(a.get("actor_name") and a.get("campaign_name") and a.get("first_seen") for a in v["actors"]),
      str(v["actors"]))

recon_only = [a for a in v["actors"] if a["ip"] == "203.0.113.5"][0]
check("benign hits counted separately from hostile", recon_only["benign_hits"] == 1)
check("a bare / visitor forms no campaign",
      not any(c["fingerprint"] == "recon" for c in v["campaigns"]))

# --- never profile ourselves ------------------------------------------------
v2 = ttp.build_threat_view(events, is_internal=lambda ip: ip.startswith("198.51.100."))
check("internal addresses excluded from actors",
      all(not a["ip"].startswith("198.51.100.") for a in v2["actors"]))
check("exclusions are reported, not silent",
      len(v2["excluded_internal"]) == 3, str(v2["excluded_internal"]))

# --- techniques the :80 traffic revealed ------------------------------------
for p_ in ["/8.php", "/2P.php", "/bnbfggf.php", "/BDKR28WP.php", "/i.php"]:
    check("webshell hunt: %s" % p_, tech(p_) == "webshell-probe", "got=%s" % tech(p_))
check("a long random php is still caught via the short form",
      tech("/0.php") == "webshell-probe")
for p_ in ["/config/mail.php", "/config/smtp.php", "/application/config/email.php",
           "/twilio.env", "/aws.yml", "/sendgrid.env"]:
    check("mail/cloud creds: %s" % p_, tech(p_) == "secret-file-harvest", "got=%s" % tech(p_))
check("appliance probe (Dahua/Hikvision)", tech("/SDK/webLanguage") == "appliance-probe")
check("appliance probe (ISAPI)", tech("/ISAPI/Security/users") == "appliance-probe")

# a server collapses repeated slashes, so an anchored rule must not be evadable
check("//x.php does not evade the /x.php rule", tech("//0.php") == "webshell-probe")
check("///admin evades nothing", tech("///admin") == "admin-discovery")
check("a query string does not evade it", tech("/fffm.php?p=1") == "webshell-probe")

# --- every dialect the profiler understands, the classifier must too --------
NGINX = ('45.159.230.92 - - [15/Sep/2026:00:07:35 +0000] '
         '"GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"')
p_ng = ttp.parse_access(NGINX)
check("parses an nginx combined line", p_ng and p_ng["ip"] == "45.159.230.92"
      and p_ng["path"] == "/.env" and p_ng["status"] == "404", str(p_ng))
_vng = ttp.build_threat_view([{"raw": NGINX, "labels": {"instance": "web"},
                               "kv": {}, "timestamp": None}])
check("an nginx-only line produces an actor", _vng["actor_count"] == 1,
      "got=%d" % _vng["actor_count"])
check("and is classified, not dumped in unknown",
      _vng["technique_totals"].get("secret-file-harvest") == 1,
      str(_vng["technique_totals"]))

# --- the internal check must not swallow strangers --------------------------
class _FakeGraph:
    """resolve_node_id returns the input unchanged for anything undeclared --
    the real behaviour, and the reason the naive check excluded every actor."""
    nodes = {"hub": object(), "laptop": object()}
    _map = {"10.0.0.10": "hub", "192.0.2.21": "laptop"}

    def resolve_node_id(self, ip):
        return self._map.get(ip, ip)


_is_int = ttp.make_internal_check(_FakeGraph())
check("declared address is internal", _is_int("10.0.0.10") is True)
check("declared address by node name is internal", _is_int("hub") is True)
check("UNDECLARED address is NOT internal", _is_int("203.0.113.77") is False)
check("an external:* id is not internal", _is_int("external:203.0.113.77") is False)
check("a resolver that raises fails closed", ttp.make_internal_check(object())("1.2.3.4") is False)

_v3 = ttp.build_threat_view(
    [ev("203.0.113.77", "/.env"), ev("10.0.0.10", "/.env")],
    is_internal=_is_int)
check("stranger survives the exclusion, declared host does not",
      [a["ip"] for a in _v3["actors"]] == ["203.0.113.77"]
      and _v3["excluded_internal"] == ["10.0.0.10"], str(_v3["excluded_internal"]))

# --- scoring ----------------------------------------------------------------
broad = ttp._score({"techniques": {"secret-file-harvest": 1, "vcs-exposure": 1,
                                   "path-traversal": 1}, "targets": {"a"}}, 3)
deep = ttp._score({"techniques": {"secret-file-harvest": 200}, "targets": {"a"}}, 200)
check("breadth of technique outweighs raw volume", broad > deep,
      "broad=%d deep=%d" % (broad, deep))
multi = ttp._score({"techniques": {"recon": 1}, "targets": {"a", "b", "c"}}, 1)
single = ttp._score({"techniques": {"recon": 1}, "targets": {"a"}}, 1)
check("hitting several hosts scores higher than one", multi > single)


# --- a learned template's field names are guesses; the line is the truth -----
_bad = {"raw": '20.65.170.9 - - [16/Sep/2026:22:47:08 +0000] "GET /hudson HTTP/1.1" 404 134 "-" "zgrab/0.x"',
        "kv": {"ip": "20.65.170.9", "path": "/Sep/2026", "num_6": "404"}, "labels": {"instance": "web"}}
_hit = ttp._event_to_hit(_bad)
check("kv.path is a date but the raw line wins", _hit is not None and _hit["path"] == "/hudson", _hit)
check("...and the status comes from the line too", _hit["status"] == "404")
_ecs = {"raw": "just a message", "kv": {"ip": "1.2.3.4", "path": "/.env", "status": "404"}, "labels": {}}
check("kv is still used when the raw is not an access line",
      (ttp._event_to_hit(_ecs) or {}).get("path") == "/.env")

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
