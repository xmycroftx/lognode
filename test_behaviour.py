#!/usr/bin/env python3
"""Claim-versus-conduct scoring. Sample lines are real, from live traffic."""
import behaviour as B

ok = True


def check(label, cond, detail=""):
    global ok
    print("  %-58s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        ok = False


def uv(ip, path, status="404", port="44699", t=0):
    return {"raw": 'INFO:     %s:%s - "GET %s HTTP/1.1" %s Not Found' % (ip, port, path, status),
            "timestamp": 1789000000 + t}


def ng(ip, path, ua, status="404", ref="-", t=0):
    return {"raw": '%s - - [15/Sep/2026:06:00:00 +0000] "GET %s HTTP/1.1" %s 134 "%s" "%s"'
                   % (ip, path, status, ref, ua),
            "timestamp": 1789000000 + t}


# --- parsing both dialects --------------------------------------------------
check("parses uvicorn", (B.parse_line(uv("1.2.3.4", "/x")["raw"]) or {}).get("ip") == "1.2.3.4")
p = B.parse_line(ng("1.2.3.4", "/x", "curl/8.0")["raw"])
check("parses nginx incl. UA", p and p["ua"] == "curl/8.0" and p["ip"] == "1.2.3.4")
check("ignores non-access lines", B.parse_line("systemd: Started foo.") is None)

# --- anachronism ------------------------------------------------------------
check("flags a 2007 Firefox",
      B.ua_anachronism("Mozilla/5.0 (X11; U; Linux i686; rv:1.8.1.9) Gecko Firefox/1.5.0.9"))
check("flags an ancient platform",
      B.ua_anachronism("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"))
check("does NOT flag a current browser",
      B.ua_anachronism("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0 Safari/537.36") is None)
check("no UA is not an anachronism", B.ua_anachronism("") is None)

# --- honest tooling scores zero deception -----------------------------------
prof = B.profile([ng("203.0.113.1", "/manager/html", "Mozilla/5.0 zgrab/0.x", t=i)
                  for i in range(30)])["203.0.113.1"]
check("self-identified scanner: inconsistency 0", prof["inconsistency"] == 0,
      "got=%d" % prof["inconsistency"])
check("self-identified scanner is still labelled",
      any("identifies itself as tooling" in t for t in prof["tells"]))

# --- a browser claim that does not behave like one --------------------------
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36"
evs = [ng("203.0.113.2", "/", CHROME, status="200", t=0)]
evs += [ng("203.0.113.2", "/p%d/.env" % i, CHROME, t=i) for i in range(1, 40)]
liar = B.profile(evs)["203.0.113.2"]
check("browser claim + no assets + no referer + wordlist scores high",
      liar["inconsistency"] >= 60, "got=%d" % liar["inconsistency"])
check("names the rendering tell",
      any("never fetched an asset" in t for t in liar["tells"]))
check("names the wordlist tell",
      any("without stopping" in t for t in liar["tells"]))

# --- a browser that behaves like one ----------------------------------------
real = B.profile([
    ng("203.0.113.3", "/", CHROME, status="200", t=0),
    ng("203.0.113.3", "/static/app.css", CHROME, status="200", ref="https://site/", t=1),
    ng("203.0.113.3", "/favicon.ico", CHROME, status="200", ref="https://site/", t=2),
])["203.0.113.3"]
check("a real browser scores 0 deception", real["inconsistency"] == 0, "got=%d" % real["inconsistency"])
check("asset fetches counted", real["asset_fetches"] == 2)

# --- UA rotation ------------------------------------------------------------
rot = B.profile([ng("203.0.113.4", "/a", "UA-%d Mozilla/5.0 Chrome/140.0" % i, t=i)
                 for i in range(5)])["203.0.113.4"]
check("rotating User-Agents is a tell",
      any("different User-Agents" in t for t in rot["tells"]))

# --- conduct-only signals, no UA available ----------------------------------
fast = B.profile([uv("203.0.113.5", "/p%d" % i, t=i // 10) for i in range(60)])["203.0.113.5"]
check("cadence tell fires without any UA", any("requests/second" in t for t in fast["tells"]))
check("single-connection tell fires", any("ONE connection" in t for t in fast["tells"]))
check("absence of UA is stated, not assumed",
      any("no User-Agent recorded" in t for t in fast["tells"]))
check("no UA means no deception score", fast["inconsistency"] == 0)

multi = B.profile([uv("203.0.113.6", "/p%d" % i, port=str(40000 + i), t=i) for i in range(15)])["203.0.113.6"]
check("many connections does not trip the keep-alive tell",
      not any("ONE connection" in t for t in multi["tells"]))

# --- event time beats ingest time -------------------------------------------
check("parses a CLF timestamp", B.clf_time("15/Sep/2026:06:04:42 +0000") is not None)
check("rejects nonsense", B.clf_time("not a date") is None)

# 30 nginx lines a minute apart, all handed the SAME ingest timestamp -- which is
# exactly what a backfill or a batched shipment looks like.
batched = []
for i in range(30):
    line = ('203.0.113.9 - - [15/Sep/2026:%02d:%02d:00 +0000] "GET /p%d HTTP/1.1" 404 134 "-" "%s"'
            % (6 + i // 60, i % 60, i, CHROME))
    batched.append({"raw": line, "timestamp": 1789000000})
b = B.profile(batched)["203.0.113.9"]
check("batched ingest does not fabricate a burst", b["peak_rate_per_s"] < 1.0,
      "rate=%s" % b["peak_rate_per_s"])
check("no scripted-cadence tell from a backfill",
      not any("requests/second" in t for t in b["tells"]))

# --- mixing two log dialects must not overclaim -----------------------------
mixed = [uv("203.0.113.10", "/p%d" % i, t=i) for i in range(12)]
mixed += [ng("203.0.113.10", "/q%d" % i, CHROME, t=100 + i) for i in range(12)]
mx = B.profile(mixed)["203.0.113.10"]
check("counts requests from both dialects", mx["requests"] == 24, "got=%d" % mx["requests"])
ka = [t for t in mx["tells"] if "ONE connection" in t]
check("keep-alive tell is scoped to port-bearing requests only",
      ka and "12 of 24" in ka[0], str(ka))

# --- crawler claims are verified, not believed ------------------------------
GB = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
check("recognises a verifiable crawler claim", B.crawler_claim(GB) == "googlebot")
check("a browser UA claims no crawler", B.crawler_claim(CHROME) is None)

def _crawl(ip, ua, rdns, n=30):
    evs = [ng(ip, "/.ssh/id_rsa", ua, t=i) for i in range(n)]
    return B.profile(evs, rdns={ip: rdns})[ip]

fake = _crawl("203.0.113.20", GB, None)
check("Googlebot with no reverse DNS is contradicted", fake["crawler_verified"] is False)
check("impersonating a whitelisted crawler scores high", fake["inconsistency"] >= 60,
      "got=%d" % fake["inconsistency"])
check("the tell names the missing reverse DNS",
      any("no reverse DNS" in t for t in fake["tells"]))

wrong = _crawl("203.0.113.21", GB, "host.example-hosting.ru")
check("Googlebot from the wrong domain is contradicted", wrong["crawler_verified"] is False)
check("the tell names what the PTR actually was",
      any("example-hosting.ru" in t for t in wrong["tells"]))

real = _crawl("66.249.66.1", GB, "crawl-66-249-66-1.googlebot.com")
check("a genuine Googlebot verifies", real["crawler_verified"] is True)
check("a genuine Googlebot scores zero deception", real["inconsistency"] == 0,
      "got=%d" % real["inconsistency"])

honest = _crawl("203.0.113.22", "Mozilla/5.0 zgrab/0.x", None)
check("an honest non-crawler scanner still scores zero", honest["inconsistency"] == 0)
check("an unverifiable bot is not punished for existing",
      B.profile([ng("203.0.113.23", "/", "SemrushBot/7~bl", t=1)],
                rdns={})["203.0.113.23"]["inconsistency"] == 0)

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
