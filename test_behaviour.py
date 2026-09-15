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

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
