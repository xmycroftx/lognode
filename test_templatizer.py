#!/usr/bin/env python3
"""The learning loop converges, and a skeleton that will not learn stops trying.

Every assertion here encodes something observed in 24 hours of production
journal: 1,881 synthesis attempts for 17 skeletons that could never be
promoted, against 58 that learned normally. The sample lines are the real
shapes that looped, so a regression here is a regression against evidence.
"""
import os, re, sys, tempfile, time
from pathlib import Path
import engine
from engine import HotPathMatcher, TemplateRule, SkeletonClusterer, OllamaTemplatizer

ok = True
def check(label, cond, detail=""):
    global ok
    print("  %-66s %s %s" % (label, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond: ok = False

def matches(rule, line):
    m = re.compile(rule.pattern).search(line)
    return bool(m) and (m.end() - m.start()) >= len(line.strip()) * engine.MIN_COVERAGE

# a matcher that starts empty and writes nowhere that matters
tmp = tempfile.mkdtemp()
M = HotPathMatcher(storage_path=Path(tmp, "base.json"),
                   runtime_path=Path(tmp, "runtime.json"))

# --- add_rule: pattern is identity, name is not ---------------------------
r1 = TemplateRule(event="fam", pattern=r"a (?P<x>\d+)")
r2 = TemplateRule(event="fam", pattern=r"b (?P<x>\d+)")
r3 = TemplateRule(event="fam", pattern=r"c (?P<x>\d+)")
check("first rule added", M.add_rule(r1) is True)
check("identical PATTERN is rejected", M.add_rule(TemplateRule(event="other", pattern=r"a (?P<x>\d+)")) is False)
check("same NAME, different pattern is ADDED (this was the deadlock)", M.add_rule(r2) is True)
check("...under a suffixed name", r2.event == "fam_2", r2.event)
check("third variant gets _3", M.add_rule(r3) is True and r3.event == "fam_3", r3.event)
check("all three are live in the matcher", len(M.rules) == 3)

# --- the skeletonizer sees key=value bare words --------------------------
S = SkeletonClusterer()
netsnap = [
    "netsnap proto=udp state=established local=203.0.113.28 local_port=40803 peer=198.51.100.53 peer_port=53 process=systemd-resolve pid=475075",
    "netsnap proto=udp state=established local=203.0.113.28 local_port=37730 peer=198.51.100.53 peer_port=53 process=docker-proxy pid=1200",
    "netsnap proto=udp state=established local=203.0.113.28 local_port=41000 peer=198.51.100.53 peer_port=53 process=- pid=7",
]
skels = {S.skeleton(l) for l in netsnap}
check("three process= variants collapse to ONE skeleton", len(skels) == 1, "%d: %s" % (len(skels), skels))
sk = next(iter(skels))
check("process value is a variable, not a literal", "process=<VAR>" in sk, sk)
check("tagged values are left alone (local=<IP>)", "local=<IP>" in sk, sk)
check("level=info becomes a variable", "level=<VAR>" in S.skeleton("ts=2026-09-16T01:00:00Z level=info msg=x"))
mac = "ssh_guard drop: IN=eth0 OUT= MAC=02:00:5e:00:53:01:fe:00:00:00:01:01:08:00 SRC=198.51.100.7 DST=203.0.113.9 LEN=60"
mac2 = "ssh_guard drop: IN=eth0 OUT= MAC=02:00:5e:00:53:02:fe:00:00:00:01:01:08:00 SRC=198.51.100.7 DST=203.0.113.9 LEN=60"
check("a MAC is one tag, not a mix of <ID> and literal octets", "MAC=<MAC>" in S.skeleton(mac), S.skeleton(mac))
check("two different MACs give the same skeleton", S.skeleton(mac) == S.skeleton(mac2))

# --- the fallback learns the families that looped ------------------------
T = OllamaTemplatizer()
rule = T.synthesize_from_skeleton(sk, netsnap)
check("netsnap family yields ONE rule", rule is not None)
check("...that matches every process variant", rule is not None and all(matches(rule, l) for l in netsnap))
check("...with the process captured as a field", rule is not None and "var" in rule.pattern.lower())

nginx = [
    '185.218.86.25 - - [16/Sep/2026:05:07:22 +0000] "GET / HTTP/1.1" 404 196 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
    '34.224.168.204 - - [16/Sep/2026:04:48:32 +0000] "GET / HTTP/1.1" 404 196 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126"',
    '213.172.73.149 - - [16/Sep/2026:04:23:40 +0000] "GET /admin/config.php HTTP/1.0" 404 162 "-" "curl/8.5.0"',
]
nsk = {S.skeleton(l) for l in nginx}
check("nginx samples share a skeleton", len(nsk) == 1, str(nsk))
nrule = T.synthesize_from_skeleton(next(iter(nsk)), nginx)
check("nginx access line is now LEARNABLE (was refused for having no name)", nrule is not None)
check("...named by its shape", nrule is not None and nrule.event.startswith("shape_"), getattr(nrule, "event", None))
check("...and matches all three samples at coverage", nrule is not None and all(matches(nrule, l) for l in nginx))

macrule = T.synthesize_from_skeleton(S.skeleton(mac), [mac, mac2, mac])
check("ssh_guard family yields a rule that matches both MACs",
      macrule is not None and matches(macrule, mac) and matches(macrule, mac2))

# --- the nginx date is a <TIME>, not a <PATH> -------------------------------
_clf = S.skeleton('20.65.170.9 - - [16/Sep/2026:22:47:08 +0000] "GET /hudson HTTP/1.1" 404 134 "-" "zgrab/0.x"')
check("CLF timestamp skeletonizes as <TIME>", "<TIME>" in _clf and "<PATH>" not in _clf.split("]")[0], _clf)
_r = T.synthesize_from_skeleton(_clf, nginx)
check("the re-learned nginx rule matches the samples", _r is not None and all(matches(_r, l) for l in nginx))
check("...and captures no field called path (the request is inside the quoted string)",
      _r is not None and "?P<path>" not in _r.pattern, getattr(_r, "pattern", "")[:120])

# --- the backoff: what stops the next unknown cause -----------------------
base, cap = engine.SYNTH_BACKOFF_BASE, engine.SYNTH_BACKOFF_MAX
check("first failure waits the base", engine.synth_backoff_seconds(1) == base)
check("second failure doubles", engine.synth_backoff_seconds(2) == 2 * base)
check("growth is capped", engine.synth_backoff_seconds(50) == cap)
check("zero failures is still the base, not zero", engine.synth_backoff_seconds(0) == base)
bo = {"s": (time.time() + 100, 1)}
check("inside the window -> skip", engine.synth_should_skip("s", bo, time.time()) is True)
check("after the window -> retry", engine.synth_should_skip("s", bo, time.time() + 101) is False)
check("unknown skeleton -> never skipped", engine.synth_should_skip("nope", bo, time.time()) is False)
check("concurrency knob defaults to 2", engine.SYNTH_CONCURRENCY == 2)

print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
