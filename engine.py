import os
import re
import json
import time
import math
import asyncio
import subprocess
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
import asyncpg
from graph import TrafficGraph
import ecs
from fields import normalize_fields

# Imported at module scope on purpose. This was originally a deferred
# `from alert import ...` inside the coroutine, which wedged the whole server:
# an import taken from inside a task can block on the import lock while another
# thread holds it, and the process sat with the main thread in futex_do_wait,
# an epoll thread that never accepted, and 104 connections queued. Import once,
# here, where it cannot deadlock a request path.
try:
    from alert import dispatch_discord_alert as _dispatch_alert
except Exception:      # alerting is optional; ingest must never depend on it
    _dispatch_alert = None

TEMPLATES_FILE = Path(os.environ.get("LOGNODE_TEMPLATES_FILE", str(Path(__file__).resolve().parent / "templates.json")))
RUNTIME_TEMPLATES_FILE = Path(os.environ.get("LOGNODE_RUNTIME_TEMPLATES_FILE", str(Path(__file__).resolve().parent / "templates.runtime.json")))

# Re-alert window for a unit that stays failed. Must be much longer than the
# collector's sweep interval, or a long-dead unit becomes a metronome.
UNIT_ALERT_COOLDOWN = int(os.environ.get("UNIT_ALERT_COOLDOWN_SECONDS", str(6 * 3600)))
# (instance|unit) -> last dispatch. In-memory: a restart re-alerts once for
# anything still failed, which is the right way round -- a restart should tell
# you what is broken, not quietly inherit an assumption that you already know.
_unit_alert_last: Dict[str, float] = {}
EVENTS_LOG_FILE = Path(str(Path(__file__).resolve().parent / "events.jsonl"))
# --- LLM backend -------------------------------------------------------------
#
# The templatizer needs any chat model that can return JSON. Two wire formats
# cover essentially everything: Ollama's native /api/chat, and the OpenAI
# /v1/chat/completions shape that LiteLLM, vLLM, llama.cpp, OpenAI, Anthropic
# via a proxy, and most others speak. Point LOGNODE_LLM_URL at either.
#
#   Ollama   LOGNODE_LLM_URL=http://localhost:11434/api/chat
#   LiteLLM  LOGNODE_LLM_URL=http://localhost:4000/v1/chat/completions
#            LOGNODE_LLM_MODEL=<whatever the router calls the model>
#            LOGNODE_LLM_API_KEY=sk-...        (sent as a bearer token)
#
# The style is inferred from the path and can be forced with LOGNODE_LLM_STYLE.
OLLAMA_URL = os.environ.get("LOGNODE_LLM_URL",
                            os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat"))
DEFAULT_MODEL = os.environ.get("LOGNODE_LLM_MODEL", "qwen2.5-coder:1.5b")
LLM_API_KEY = os.environ.get("LOGNODE_LLM_API_KEY", "")
LLM_TIMEOUT = int(os.environ.get("LOGNODE_LLM_TIMEOUT", "15"))


def detect_llm_style(url: str) -> str:
    """'openai' for /v1/chat/completions-shaped endpoints, else 'ollama'."""
    forced = os.environ.get("LOGNODE_LLM_STYLE", "").strip().lower()
    if forced in ("openai", "ollama"):
        return forced
    return "openai" if "/chat/completions" in url or "/v1" in url else "ollama"
POSTGRES_DSN = os.environ.get(
    "LOGNODE_POSTGRES_DSN",
    "postgresql://lognode@localhost:5432/lognode",
)

# --- synthesis backoff --------------------------------------------------------
#
# A skeleton whose synthesis did not produce a promoted rule is not retried on
# the next three samples. It used to be: the bucket refilled in about seventy
# seconds and fired again, forever. Twelve hours of journal held 1,176 LLM
# calls for 45 distinct skeletons; three of them accounted for 94%. The fixes
# above remove the causes that were known. This is what stops the NEXT unknown
# cause from doing the same thing, whatever it turns out to be.
SYNTH_BACKOFF_BASE = int(os.environ.get("LOGNODE_SYNTH_BACKOFF", "600"))
SYNTH_BACKOFF_MAX = int(os.environ.get("LOGNODE_SYNTH_BACKOFF_MAX", str(6 * 3600)))
SYNTH_CONCURRENCY = int(os.environ.get("LOGNODE_SYNTH_CONCURRENCY", "2"))


def synth_backoff_seconds(failures: int) -> float:
    """Exponential from the base, capped. failures is 1 on the first miss."""
    return float(min(SYNTH_BACKOFF_MAX, SYNTH_BACKOFF_BASE * (2 ** max(0, failures - 1))))


def synth_should_skip(skel: str, backoff: Dict[str, Tuple[float, int]], now: float) -> bool:
    """True while a skeleton is inside its backoff window."""
    entry = backoff.get(skel)
    return bool(entry) and now < entry[0]


# Fraction of a line a regex must span to count as a match.
# This MUST be the same value at validation time and at match time. When they
# differed (validate 0.40 / match 0.70), any rule covering 40-69%% of a line
# validated, was promoted, was written to templates.json -- and then never
# matched anything at runtime. Silent dead rules.
MIN_COVERAGE = 0.70

@dataclass
class TemplateRule:
    event: str
    pattern: str
    fields: List[str] = field(default_factory=list)
    hit_count: int = 0
    created_at: float = field(default_factory=time.time)
    _compiled: Optional[Any] = field(default=None, repr=False)

    def compile(self) -> bool:
        try:
            self._compiled = re.compile(self.pattern)
            return True
        except re.error as e:
            print(f"[Matcher] Regex compile error for {self.event}: {e}")
            return False

    def match(self, line: str) -> Optional[Dict[str, str]]:
        if not self._compiled and not self.compile():
            return None
        m = self._compiled.search(line)
        if m:
            stripped = line.strip()
            if not stripped:
                return None
            matched_len = m.end() - m.start()
            if matched_len < len(stripped) * MIN_COVERAGE:
                return None
            self.hit_count += 1
            return m.groupdict()
        return None

class HotPathMatcher:
    def __init__(self, storage_path: Path = TEMPLATES_FILE, runtime_path: Path = RUNTIME_TEMPLATES_FILE):
        self.storage_path = storage_path
        self.runtime_path = runtime_path
        self.rules: List[TemplateRule] = []
        self.runtime_rules: List[TemplateRule] = []
        self.load()

    def load(self):
        self.rules = []
        self.runtime_rules = []
        base_count = 0

        # 1. Load base templates (tracked in git)
        if self.storage_path.exists():
            try:
                with open(self.storage_path, "r") as f:
                    data = json.load(f)
                for item in data:
                    rule = TemplateRule(
                        event=item["event"],
                        pattern=item["pattern"],
                        fields=item.get("fields", []),
                        hit_count=item.get("hit_count", 0),
                        created_at=item.get("created_at", time.time())
                    )
                    if rule.compile():
                        self.rules.append(rule)
                base_count = len(self.rules)
            except Exception as e:
                print(f"[HotPath] Error loading base templates: {e}")

        # 2. Load dynamic runtime templates (untracked in git)
        if self.runtime_path.exists():
            try:
                with open(self.runtime_path, "r") as f:
                    data = json.load(f)
                existing_patterns = {r.pattern for r in self.rules}
                existing_events = {r.event for r in self.rules}
                for item in data:
                    if item["pattern"] in existing_patterns or item["event"] in existing_events:
                        continue
                    rule = TemplateRule(
                        event=item["event"],
                        pattern=item["pattern"],
                        fields=item.get("fields", []),
                        hit_count=item.get("hit_count", 0),
                        created_at=item.get("created_at", time.time())
                    )
                    if rule.compile():
                        self.rules.insert(0, rule)
                        self.runtime_rules.append(rule)
                        existing_patterns.add(rule.pattern)
                        existing_events.add(rule.event)
            except Exception as e:
                print(f"[HotPath] Error loading runtime templates: {e}")

        print(f"[HotPath] Loaded {base_count} base templates and {len(self.runtime_rules)} runtime templates (total: {len(self.rules)})")

    def save_runtime(self):
        """Persists newly synthesized runtime templates to untracked runtime file."""
        try:
            data = [
                {
                    "event": r.event,
                    "pattern": r.pattern,
                    "fields": r.fields,
                    "hit_count": r.hit_count,
                    "created_at": r.created_at
                }
                for r in self.runtime_rules
            ]
            with open(self.runtime_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[HotPath] Error saving runtime templates: {e}")

    def add_rule(self, rule: TemplateRule) -> bool:
        """Add a learned rule. True only if it was actually added.

        A duplicate is judged by PATTERN, never by event name. The fallback
        names a rule from the first four words of its skeleton, so every
        variant of a family -- process=docker-proxy, process=systemd-resolve
        -- arrives with the same name. Rejecting on the name meant that once
        one variant owned it, the rest of the family was unlearnable forever:
        1,134 re-syntheses of a single netsnap skeleton in 24 hours, each one
        producing a valid rule and each one discarded here without a word.
        A colliding name gets a numeric suffix instead.
        """
        if not rule.compile():
            return False
        if any(r.pattern == rule.pattern for r in self.rules):
            return False
        taken = {r.event for r in self.rules}
        if rule.event in taken:
            n = 2
            while "%s_%d" % (rule.event, n) in taken:
                n += 1
            rule.event = "%s_%d" % (rule.event, n)
        self.rules.insert(0, rule)
        self.runtime_rules.insert(0, rule)
        self.save_runtime()
        return True

    def sync_to_base(self, commit_to_git: bool = False) -> Dict[str, Any]:
        """Merges runtime templates into base templates.json and optionally commits to git."""
        if not self.runtime_path.exists():
            return {"status": "no_runtime_templates", "merged_count": 0, "total_base": len(self.rules)}

        try:
            with open(self.runtime_path, "r") as f:
                runtime_data = json.load(f)
        except Exception as e:
            return {"status": "error", "error": f"Failed reading runtime templates: {e}"}

        if not runtime_data:
            return {"status": "empty", "merged_count": 0, "total_base": len(self.rules)}

        base_data = []
        if self.storage_path.exists():
            try:
                with open(self.storage_path, "r") as f:
                    base_data = json.load(f)
            except Exception as e:
                return {"status": "error", "error": f"Failed reading base templates: {e}"}

        existing_events = {item["event"] for item in base_data}
        existing_patterns = {item["pattern"] for item in base_data}

        merged_items = []
        for item in runtime_data:
            if item["event"] not in existing_events and item["pattern"] not in existing_patterns:
                base_data.insert(0, item)
                existing_events.add(item["event"])
                existing_patterns.add(item["pattern"])
                merged_items.append(item["event"])

        try:
            with open(self.storage_path, "w") as f:
                json.dump(base_data, f, indent=2)

            self.runtime_rules = []
            with open(self.runtime_path, "w") as f:
                json.dump([], f)
        except Exception as e:
            return {"status": "error", "error": f"Failed writing merged templates: {e}"}

        git_committed = False
        commit_msg = ""
        if commit_to_git and merged_items:
            try:
                msg = f"feat(templates): sync {len(merged_items)} learned runtime templates into repo"
                proc = subprocess.run(
                    ["git", "add", str(self.storage_path)],
                    cwd=str(self.storage_path.parent),
                    capture_output=True,
                    text=True
                )
                if proc.returncode == 0:
                    cproc = subprocess.run(
                        ["git", "commit", "-m", msg],
                        cwd=str(self.storage_path.parent),
                        capture_output=True,
                        text=True
                    )
                    git_committed = (cproc.returncode == 0)
                    commit_msg = msg if git_committed else cproc.stderr
            except Exception as ge:
                commit_msg = str(ge)

        return {
            "status": "synced",
            "merged_count": len(merged_items),
            "merged_events": merged_items[:20],
            "total_base": len(base_data),
            "git_committed": git_committed,
            "commit_msg": commit_msg
        }

    def match(self, line: str) -> Optional[Tuple[str, Dict[str, str]]]:
        for rule in self.rules:
            kv = rule.match(line)
            if kv is not None:
                return rule.event, kv
        return None

class SkeletonClusterer:
    """Masks high-entropy literals to cluster log lines into template buckets."""
    TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b")
    IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
    # Before HEX/ID/NUM, which would otherwise carve a MAC into an inconsistent
    # mix of tagged and literal octets -- d6 is an <ID>, 8a is not, cf is not --
    # so every distinct address produced a distinct skeleton, and every one of
    # them collided on the same rule name. 213 re-syntheses a day for ssh_guard.
    MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5,}[0-9a-fA-F]{2}\b")
    # Must contain a letter. A run of 6+ digits is a pid, a size, an id -- a
    # number -- and tagging it <HEX> because it happens to be hex-alphabet
    # split every family by digit COUNT: pid=1200 was <NUM>, pid=475075 was
    # <HEX>, two skeletons, two rules, and a misleading field name in kv.
    HEX_RE = re.compile(r"\b(?:0x)?(?=[a-f0-9]*[a-f])[a-f0-9]{6,64}\b", re.IGNORECASE)
    PATH_RE = re.compile(r"(?:/[a-zA-Z0-9_\.\-]+){2,}")
    ID_RE = re.compile(r"\b[A-Za-z_]+[0-9]+[A-Za-z0-9_]*\b")
    NUM_RE = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|us|B|KB|MB|GB)?\b")
    STR_RE = re.compile(r'"[^"]*"|\'[^\']*\'')
    PREP_RE = re.compile(r"\b(from|to|at|in|by|on|for|user|zone|server|peer|host|session|client)\s+([A-Za-z0-9_\-\.]+)\b", re.IGNORECASE)
    # key=value where the value is a bare word. Nothing above tags these: a
    # word with no digit is not an <ID>, "process" is not a PREP_RE keyword,
    # and "=" is not whitespace. So process=docker-proxy froze into a rule as a
    # LITERAL and process=systemd-resolve -- 3,600 lines a day -- could never
    # match it. Runs last so tagged values (local=<IP>) are left alone.
    KV_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=([A-Za-z][A-Za-z0-9_\-\.]*|-)(?=\s|$)")

    def __init__(self, cluster_threshold: int = 3, max_buckets: int = 2000):
        self.cluster_threshold = cluster_threshold
        self.max_buckets = max_buckets
        self.buckets: Dict[str, List[str]] = {}

    def skeleton(self, line: str) -> str:
        s = self.TIME_RE.sub("<TIME>", line)
        s = self.IP_RE.sub("<IP>", s)
        s = self.MAC_RE.sub("<MAC>", s)
        s = self.HEX_RE.sub("<HEX>", s)
        s = self.PATH_RE.sub("<PATH>", s)
        s = self.STR_RE.sub("<STR>", s)
        s = self.ID_RE.sub("<ID>", s)
        s = self.NUM_RE.sub("<NUM>", s)
        s = self.PREP_RE.sub(r"\1 <VAR>", s)
        s = self.KV_RE.sub(r"\1=<VAR>", s)
        return s

    def add(self, line: str) -> Optional[Tuple[str, List[str]]]:
        skel = self.skeleton(line)
        if skel not in self.buckets:
            if len(self.buckets) >= self.max_buckets:
                oldest_key = next(iter(self.buckets))
                self.buckets.pop(oldest_key, None)
            self.buckets[skel] = []
        self.buckets[skel].append(line)

        if len(self.buckets[skel]) >= self.cluster_threshold:
            samples = self.buckets.pop(skel)
            return skel, samples
        return None

def _strip_leading_group(pattern: str, name: str) -> str:
    """Remove a leading (?P<name>...) group, honouring nested parentheses.

    The previous implementation was re.sub(r"^\\(\\?P<timestamp>[^)]+\\)", ...).
    [^)]+ stops at the FIRST ')', so a perfectly good group containing a nested
    one -- e.g. (?P<timestamp>[\\d:.]+(?:Z)?) -- was truncated mid-pattern and the
    surviving text was a corrupt regex. It turned correct model output into a
    failure. This walks the parentheses instead.
    """
    prefix = f"(?P<{name}>"
    if not pattern.startswith(prefix):
        return pattern
    depth = 0
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return pattern[i + 1:].lstrip()
        i += 1
    return pattern  # unbalanced -- leave it alone rather than mangle it


class OllamaTemplatizer:
    def __init__(self, model: str = DEFAULT_MODEL, api_url: str = OLLAMA_URL,
                 api_key: str = LLM_API_KEY, style: Optional[str] = None):
        self.model = model
        self.api_url = api_url
        self.api_key = api_key
        self.style = style or detect_llm_style(api_url)

    def _build_payload(self, system_msg: str, user_msg: str) -> Dict[str, Any]:
        messages = [{"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg}]
        if self.style == "openai":
            # response_format is honoured by OpenAI and by LiteLLM for providers
            # that support it, and ignored by those that do not -- the prompt
            # already demands JSON, so this is belt and braces rather than load
            # bearing.
            return {
                "model": self.model,
                "messages": messages,
                "temperature": 0.0,
                "max_tokens": 384,
                "stream": False,
                "response_format": {"type": "json_object"},
            }
        return {
            "model": self.model,
            "messages": messages,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 384},
        }

    def _extract_content(self, result: Dict[str, Any]) -> str:
        """Pull the assistant text out of either wire format.

        Both shapes have a reasoning-model variant that leaves `content` empty
        and puts the answer elsewhere; missing that cost us a KeyError that
        surfaced as a generic call failure, so both are handled here.
        """
        if self.style == "openai":
            choices = result.get("choices") or []
            message = (choices[0].get("message") or {}) if choices else {}
            return (message.get("content")
                    or message.get("reasoning_content")
                    or message.get("reasoning")
                    or "")
        message = result.get("message") or {}
        return message.get("content") or message.get("reasoning") or ""

    def _call_ollama(self, samples: List[str]) -> Optional[TemplateRule]:
        formatted_samples = "\n".join(f"Line {i+1}: {line}" for i, line in enumerate(samples[:5]))
        system_msg = (
            "You are a high-speed log regex generator. You will receive sample lines from the exact same log event. "
            "Output strictly valid JSON with \"event\" (concise snake_case) and \"regex\". "
            "CRITICAL RULES:\n"
            "1. The regex must match the lines character-for-character, using named capture groups (?P<var>...) for dynamic values.\n"
            "2. NEVER invent or prepend a timestamp regex unless the sample lines literally start with a timestamp! If a line starts with '[', a service name, or a tag, your regex MUST start with that exact prefix.\n"
            "4. Prefer these capture-group names so fields are queryable across templates: "
            "ip, host, port, path, url, mac, uuid, user, pid, duration, bytes. "
            "Keep a role prefix when direction matters: src_ip, dst_ip, client_ip, remote_ip.\n"
            "3. Escape EVERY regex metacharacter that appears literally in the line: "
            "\\[ \\] \\( \\) \\{ \\} \\| \\. \\+ \\* \\? \\^ \\$ \\\\.\n"
            "   A literal pipe is common in slot/worker logs ('id 1 | task 2') and an "
            "unescaped | is ALTERNATION, which silently matches a fragment.\n\n"
            "Example 1 (Bracketed tag, no timestamp):\n"
            "Line 1: [meshtelem] FileNotFoundError: [Errno 2] No such file: '/dev/tty1'\n"
            "Line 2: [meshtelem] FileNotFoundError: [Errno 2] No such file: '/dev/tty2'\n"
            "Output:\n"
            "{\"event\": \"meshtelem_file_not_found\", \"regex\": \"\\\\[meshtelem\\\\] FileNotFoundError: \\\\[Errno (?P<errno>\\\\d+)\\\\] No such file: '(?P<device>[^']+)'\"}\n\n"
            "Example 2 (Logfmt key-value):\n"
            "Line 1: time=\"2026-09-13T12:00:01Z\" level=error msg=\"dial tcp 10.0.0.1: timeout\"\n"
            "Line 2: time=\"2026-09-13T12:00:02Z\" level=error msg=\"dial tcp 10.0.0.2: timeout\"\n"
            "Output:\n"
            "{\"event\": \"service_dial_timeout\", \"regex\": \"time=\\\"(?P<timestamp>[^\\\"]+)\\\" level=(?P<level>\\\\w+) msg=\\\"(?P<msg>[^\\\"]+)\\\"\"}\n\n"
            "Example 3 (Timestamp prefix):\n"
            "Line 1: 2026-09-13 12:00:01.100 A sshd[123] User root logged in\n"
            "Line 2: 2026-09-13 12:00:02.200 A sshd[124] User admin logged in\n"
            "Output:\n"
            "{\"event\": \"sshd_user_login\", \"regex\": \"(?P<timestamp>[\\\\d-]+ [\\\\d:.]+) A\\\\s+sshd\\\\[(?P<pid>\\\\d+)\\\\] User (?P<user>[\\\\w]+) logged in\"}"
        )
        user_msg = (
            f"Here are sample log lines of the exact same event type:\n{formatted_samples}\n\n"
            "Generate the regex matching these lines with named capture groups for the variables."
        )

        payload = self._build_payload(system_msg, user_msg)

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key

        req = urllib.request.Request(
            self.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers
        )

        try:
            start_t = time.time()
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            elapsed = time.time() - start_t

            content = self._extract_content(result)
            if not content.strip():
                # Reasoning models return the answer under 'reasoning' and leave
                # 'content' empty or absent. Previously this raised KeyError, was
                # swallowed by the except below, and surfaced as "Error calling
                # Ollama" -- indistinguishable from a genuine timeout.
                content = content or ""
                if content.strip():
                    m_json = re.search(r"\{.*\}", content, re.S)
                    if m_json:
                        content = m_json.group(0)
            if not content.strip():
                print("[Templatizer] Model returned no content and no reasoning; "
                      "check the model is not thinking-only.")
                return None
            parsed_json = json.loads(content)
            event_name = parsed_json.get("event", "unknown_event")
            raw_regex = parsed_json.get("regex", "")

            # If model hallucinated a leading timestamp group but lines don't start with digits, strip it
            if not any(re.match(r"^\d", s.strip()) for s in samples):
                raw_regex = _strip_leading_group(raw_regex, "timestamp")

            try:
                compiled = re.compile(raw_regex)
            except re.error as e:
                print(f"[Templatizer] Model generated invalid regex: {e}\nRegex was: {raw_regex}")
                return None

            # Negative control check: candidate regex must not match random control lines
            control_samples = [
                "XYZ_CONTROL_TEST_LINE_99999_ALPHA_BETA",
                "Completely unrelated kernel error on dev /dev/null"
            ]
            for c_line in control_samples:
                if compiled.search(c_line):
                    print(f"[Templatizer] Validation failed: matched negative control string: {raw_regex}")
                    return None

            match_count = 0
            extracted_fields = set()
            for line in samples:
                m = compiled.search(line)
                if m:
                    stripped = line.strip()
                    if stripped and (m.end() - m.start()) >= len(stripped) * MIN_COVERAGE:
                        match_count += 1
                        extracted_fields.update(m.groupdict().keys())

            min_required = max(1, len(samples) - 1)
            if match_count >= min_required:
                print(f"[Templatizer] SUCCESS ({elapsed*1000:.1f}ms): Event '{event_name}' validated on {match_count}/{len(samples)} samples. Fields: {sorted(list(extracted_fields))}")
                return TemplateRule(
                    event=event_name,
                    pattern=raw_regex,
                    fields=sorted(list(extracted_fields))
                )
            else:
                print(f"[Templatizer] Validation failed: matched {match_count}/{len(samples)} lines with pattern: {raw_regex}")
                return None

        except Exception as e:
            print(f"[Templatizer] Error calling Ollama: {e}")
            return None

    def synthesize_from_skeleton(self, skel: str, samples: List[str]) -> Optional[TemplateRule]:
        """Deterministic zero-waste fallback synthesizing a valid regex directly from skeleton structure."""
        clean = re.sub(r"<[A-Z]+>", "", skel)
        clean = re.sub(r"[^a-zA-Z0-9_\s]", " ", clean)
        words = [
            w.lower() for w in clean.split()
            if len(w) > 1 and not w.isdigit()
            and w.lower() not in ("line", "info", "error", "warn", "warning", "to", "from", "at", "in", "by", "for", "the", "a", "an")
        ]
        if words:
            event_name = "_".join(words[:4])
        else:
            # An all-tag skeleton -- the nginx access line is nothing but
            # <IP> <NUM> <PATH> <STR> and punctuation -- has no words to name
            # itself with. It used to be refused outright, AFTER building a
            # regex that matched 3/3 samples at full coverage: a perfect rule
            # thrown away for want of a name, 373 times a day, for the single
            # most security-relevant line shape in the fleet. Name it by its
            # shape instead.
            seen = []
            for t in re.findall(r"<([A-Z]+)>", skel):
                if t.lower() not in seen:
                    seen.append(t.lower())
            event_name = "shape_" + "_".join(seen[:4]) if seen else "unstructured_event"

        TAG_PATTERNS = {
            "<TIME>": r"[\d-]+[T ][\d:.]+(?:Z|[+-]\d{2}:\d{2})?",
            "<IP>": r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?",
            "<HEX>": r"(?:0x)?[a-fA-F0-9]+",
            "<PATH>": r"(?:/[a-zA-Z0-9_\.\-]+)+",
            "<STR>": r'"[^"]*"|\'[^\']*\'',
            "<NUM>": r"\d+(?:\.\d+)?(?:ms|s|us|B|KB|MB|GB)?",
            "<ID>": r"[A-Za-z_]+[0-9]+[A-Za-z0-9_]*",
            "<VAR>": r"[A-Za-z0-9_\-\.]+",
            "<MAC>": r"(?:[0-9a-fA-F]{2}:){5,}[0-9a-fA-F]{2}",
        }

        parts = re.split(r"(<[A-Z]+>)", skel)
        regex_parts = []
        group_counts = {}
        for p in parts:
            if p in TAG_PATTERNS:
                g_base = p.strip("<>").lower()
                idx = group_counts.get(g_base, 0) + 1
                group_counts[g_base] = idx
                g_name = f"{g_base}_{idx}" if idx > 1 else g_base
                regex_parts.append(f"(?P<{g_name}>{TAG_PATTERNS[p]})")
            else:
                regex_parts.append(re.escape(p))

        raw_regex = "".join(regex_parts)
        try:
            compiled = re.compile(raw_regex)
        except Exception as e:
            print(f"[Templatizer] Skeleton regex compilation error: {e}")
            return None

        if event_name == "unstructured_event" or len(raw_regex.strip()) < 5:
            return None

        match_count = 0
        for line in samples:
            m = compiled.search(line)
            if m:
                stripped = line.strip()
                if stripped and (m.end() - m.start()) >= len(stripped) * MIN_COVERAGE:
                    match_count += 1

        min_required = max(1, len(samples) - 1)
        if match_count >= min_required:
            fields = sorted(list(compiled.groupindex.keys()))
            print(f"[Templatizer] Deterministic Skeleton SUCCESS: Event '{event_name}' on {match_count}/{len(samples)} samples. Fields: {fields}")
            return TemplateRule(
                event=event_name,
                pattern=raw_regex,
                fields=fields
            )
        return None

    async def synthesize_async(self, samples: List[str]) -> Optional[TemplateRule]:
        return await asyncio.to_thread(self._call_ollama, samples)

class PostgresSink:
    def __init__(self, dsn: str = POSTGRES_DSN):
        self.dsn = dsn
        self.pool: Optional[asyncpg.Pool] = None
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=50000)
        # Loss counters. Both paths below already existed and both were silent;
        # these only make them countable, and are exported on /metrics.
        self.dropped_no_pool = 0
        self.dropped_flush_error = 0
        self._worker_task: Optional[asyncio.Task] = None
        self.on_flush: Optional[Any] = None

    async def start(self):
        try:
            self.pool = await asyncpg.create_pool(self.dsn, min_size=2, max_size=10)
            self._worker_task = asyncio.create_task(self._flusher())
            print("[Postgres] Connected to PostgreSQL pool and started flusher.")
        except Exception as e:
            print(f"[Postgres] Warning: Could not connect to Postgres: {e}")

    async def enqueue(self, event: str, kv: Dict[str, Any], raw: str,
                      labels: Optional[Dict[str, Any]] = None,
                      latency_us: Optional[float] = None,
                      ts: Optional[float] = None):
        """Queue one row. `ts` is the event's OWN time, if it has one.

        Callers that do not pass `ts` get the column default, so every existing
        one is unaffected. Callers that do -- anything arriving from a shipper
        with a queue in front of it -- get the time the event happened rather
        than the time it reached us, which for a replayed backlog are hours
        apart. Stamping ingest time on a replay is what made 486 backfilled
        lines read as a single burst and invent cadence tells that never were.
        """
        if not self.pool:
            # Every line discarded here is discarded silently, and /ingest still
            # answers "matched". Counting them is the difference between a
            # deliberate best-effort design and an undetected outage.
            self.dropped_no_pool += 1
            return
        await self.queue.put((
            event,
            json.dumps(labels or {}),
            json.dumps(kv or {}),
            latency_us,
            raw,
            ts
        ))

    async def _flusher(self):
        while True:
            batch = []
            try:
                item = await self.queue.get()
                batch.append(item)
                self.queue.task_done()

                # Gather up to 1000 queued records for high-throughput batching
                while len(batch) < 1000 and not self.queue.empty():
                    batch.append(self.queue.get_nowait())
                    self.queue.task_done()

                if batch and self.pool:
                    async with self.pool.acquire() as conn:
                        await conn.executemany(
                            """
                            INSERT INTO log_events (event, labels, kv, latency_us, raw, timestamp)
                            VALUES ($1, $2::jsonb, $3::jsonb, $4, $5,
                                    COALESCE(to_timestamp($6::double precision), now()))
                            """,
                            batch
                        )
                    if self.on_flush:
                        try:
                            self.on_flush(len(batch))
                        except Exception:
                            pass
            except asyncio.CancelledError:
                break
            except Exception as e:
                # The batch is gone -- there is no retry and no dead-letter. That
                # is a deliberate best-effort choice, but an uncounted one is
                # indistinguishable from a working system, so say how much.
                self.dropped_flush_error += len(batch)
                print(f"[Postgres] Flusher error ({len(batch)} rows dropped, "
                      f"{self.dropped_flush_error} total): {e}")
                await asyncio.sleep(0.5)

    # A value safe to splice into a jsonpath literal. jsonpath cannot be
    # parameterised through the @? operator without losing the GIN index, so
    # instead of escaping we allow only characters that appear in the things
    # anyone actually searches for -- addresses, hostnames, users, paths, ids --
    # and reject the rest. Nothing here can close a jsonpath string literal.
    _SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:/@+-]{1,128}$")

    # The furthest this will ever go in one statement. Not a policy knob -- the
    # per-request ceiling belongs at the HTTP and MCP surfaces, where the caller
    # is untrusted. This one exists only so a bug cannot ask for the whole table.
    HARD_ROW_CAP = 200_000

    def _build_filters(
        self,
        event: Optional[str] = None,
        instance: Optional[str] = None,
        source: Optional[str] = None,
        q: Optional[str] = None,
        value: Optional[str] = None,
        kv: Optional[str] = None,
        since_s: Optional[int] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        port: Optional[Any] = None,
        process: Optional[str] = None,
        network_only: bool = False,
    ):
        """-> (where_clause, params).

        Shared by query_logs and count_logs so the two cannot drift. A count
        built from a second, hand-written WHERE would eventually disagree with
        the rows it claims to be counting, and it would disagree silently.
        """
        conditions = []
        params = []

        if event:
            params.append(event)
            conditions.append(f"event = ${len(params)}")

        if instance:
            params.append(instance)
            conditions.append(f"(labels->>'instance') = ${len(params)}")

        if source:
            params.append(source)
            conditions.append(f"(labels->>'source') = ${len(params)}")

        if q:
            params.append(f"%{q}%")
            conditions.append(f"raw ILIKE ${len(params)}")

        if network_only:
            conditions.append("(event LIKE 'netsnap%' OR (labels->>'source') = 'netsnap' OR event IN ('publickey_accepted', 'sshd_session', 'sshd', 'query_result', 'dnsmasq'))")

        # Find a value under ANY kv key, across every host.
        #
        # The obvious version -- kv @> {"ip": X} -- is wrong, and quietly so.
        # fields.py adds a bare `ip` alias for the PRIMARY address only, so a
        # netsnap row reads ip=local_ip with the far end in peer_ip. Searching
        # the alias for 198.51.100.10 returned 0 rows on a table where the
        # any-key form returned 4,034. A search that silently answers "nothing"
        # is worse than one that is slow.
        #
        # @? with a literal jsonpath is GIN-indexable: measured at 1.7ms against
        # 3M rows (Bitmap Index Scan on idx_events_kv).
        if value:
            if not self._SAFE_VALUE.match(value):
                raise ValueError("value contains characters that are not searchable")
            params.append('$.* ? (@ == "%s")' % value)
            conditions.append(f"kv @? ${len(params)}::jsonpath")

        # Exact field match, "key:value" -- for when the role matters, e.g.
        # peer_ip:1.2.3.4 rather than "this address anywhere". Parameterised, so
        # no escaping question arises, and served by the same GIN index.
        if kv:
            key, _, val = kv.partition(":")
            if not key or not val:
                raise ValueError("kv filter must be key:value")
            params.append(key)
            params.append(val)
            conditions.append(
                f"kv @> jsonb_build_object(${len(params) - 1}::text, ${len(params)}::text)"
            )

        if port is not None and str(port).strip():
            port_str = str(port).strip()
            params.append(port_str)
            p_idx = len(params)
            conditions.append(f"((kv->>'local_port') = ${p_idx} OR (kv->>'peer_port') = ${p_idx})")

        if process:
            params.append(process)
            conditions.append(f"(kv->>'process') = ${len(params)}")

        if start_time is not None:
            params.append(float(start_time))
            conditions.append(f"timestamp >= to_timestamp(${len(params)})")

        if end_time is not None:
            params.append(float(end_time))
            conditions.append(f"timestamp <= to_timestamp(${len(params)})")

        if since_s and start_time is None:
            params.append(since_s)
            conditions.append(f"timestamp >= NOW() - (${len(params)} * INTERVAL '1 second')")

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        return where_clause, params

    async def count_logs(self, **filters) -> int:
        """How many rows MATCH, as opposed to how many were returned.

        /threats asked for 5000 rows over 24h, silently received 1000, and
        reported "1000 events scanned" -- so a 24-hour page was in fact showing
        the most recent six and a half hours, with nothing on it saying so. The
        row count is the only way the caller can tell the difference between
        "that is all of it" and "that is where we stopped reading".

        Measured at 52ms for a 7-day trigram-filtered count over 3.25M rows.
        """
        if not self.pool:
            return 0
        where_clause, params = self._build_filters(**filters)
        async with self.pool.acquire() as conn:
            return int(await conn.fetchval(
                f"SELECT count(*) FROM log_events {where_clause}", *params))

    async def query_logs(
        self,
        event: Optional[str] = None,
        instance: Optional[str] = None,
        source: Optional[str] = None,
        q: Optional[str] = None,
        value: Optional[str] = None,
        kv: Optional[str] = None,
        since_s: Optional[int] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        port: Optional[Any] = None,
        process: Optional[str] = None,
        network_only: bool = False,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        if not self.pool:
            return []

        where_clause, params = self._build_filters(
            event=event, instance=instance, source=source, q=q,
            value=value, kv=kv, since_s=since_s, start_time=start_time,
            end_time=end_time, port=port, process=process, network_only=network_only)

        params.append(max(1, min(limit, self.HARD_ROW_CAP)))
        limit_param = f"${len(params)}"

        query = f"""
            SELECT id, timestamp, event, labels, kv, latency_us, raw
            FROM log_events
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT {limit_param}
        """

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [
                {
                    "id": r["id"],
                    "timestamp": r["timestamp"].isoformat(),
                    "event": r["event"],
                    "labels": json.loads(r["labels"]) if isinstance(r["labels"], str) else r["labels"],
                    "kv": json.loads(r["kv"]) if isinstance(r["kv"], str) else r["kv"],
                    "latency_us": r["latency_us"],
                    "raw": r["raw"]
                }
                for r in rows
            ]

    async def query_recent(self, event: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        return await self.query_logs(event=event, limit=limit)

    async def query_network_events(
        self,
        ip: Optional[str] = None,
        port: Optional[Any] = None,
        instance: Optional[str] = None,
        process: Optional[str] = None,
        protocol: Optional[str] = None,
        since_s: Optional[int] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Queries structured socket and network events across the fleet."""
        event_filter = None
        if protocol == "ssh":
            event_filter = "publickey_accepted"
        elif protocol == "dns":
            event_filter = "query_result"
        return await self.query_logs(
            event=event_filter,
            instance=instance,
            value=ip,
            port=port,
            process=process,
            since_s=since_s,
            start_time=start_time,
            end_time=end_time,
            network_only=True,
            limit=limit
        )

    async def close(self):
        if self._worker_task:
            self._worker_task.cancel()
        if self.pool:
            await self.pool.close()


CRITICAL_LOG_PATTERN = re.compile(
    r"\b(kernel oops|oom-killer|out of memory|segfault|segmentation fault|panic|machine check error|hardware error|ext4-fs error|btrfs: error)\b",
    re.I
)

DEFAULT_WARMUP_SECONDS = int(os.environ.get("ALERT_WARMUP_SECONDS", "900"))  # 15 minutes default

class AnomalyDetector:
    """Tracks sliding event frequencies, calibrates baselines, and arms alerts only when stable."""
    def __init__(self, check_interval: int = 15, warmup_seconds: int = DEFAULT_WARMUP_SECONDS):
        self.check_interval = check_interval
        self.warmup_seconds = warmup_seconds
        self.start_time = time.time()
        self.is_armed = False
        self.armed_at: Optional[float] = None
        self.pg_sink: Optional[PostgresSink] = None
        # (instance, event) -> deque of timestamps in last 15 min
        self.event_timestamps = defaultdict(lambda: deque())
        # instance -> deque of timestamps of all events
        self.instance_total_timestamps = defaultdict(lambda: deque())
        # instance -> deque of timestamps of unstructured events
        self.instance_unstructured_timestamps = defaultdict(lambda: deque())
        self.active_anomalies: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None

    @property
    def calibration_status(self) -> Dict[str, Any]:
        uptime = time.time() - self.start_time
        remaining = max(0, int(self.warmup_seconds - uptime))
        queue_size = self.pg_sink.queue.qsize() if self.pg_sink else 0
        return {
            "state": "ARMED" if self.is_armed else "CALIBRATING",
            "uptime_seconds": round(uptime, 1),
            "warmup_seconds": self.warmup_seconds,
            "seconds_remaining": remaining,
            "queue_depth": queue_size,
            "queue_settled": queue_size < 500,
            "is_armed": self.is_armed
        }

    def record_event(self, instance: str, event: str, raw: str, kv: dict):
        now = time.time()
        key = (instance, event)
        self.event_timestamps[key].append(now)
        self.instance_total_timestamps[instance].append(now)
        if event == "unstructured":
            self.instance_unstructured_timestamps[instance].append(now)

        # Immediate Critical Hardware/Kernel Watchdog (fires even during calibration)
        if CRITICAL_LOG_PATTERN.search(raw):
            asyncio.create_task(self._trigger_critical_event(instance, event, raw, kv))

    async def _trigger_critical_event(self, instance: str, event: str, raw: str, kv: dict):
        try:
            from alert import dispatch_discord_alert
            await dispatch_discord_alert(
                title=f"Critical Hardware/Kernel Event on {instance}",
                description="Log message matched high-severity critical pattern watchdog.",
                severity="critical",
                instance=instance,
                event=event,
                kv=kv,
                raw_sample=raw,
                force=True
            )
        except Exception as e:
            print(f"[AnomalyDetector] Failed to dispatch critical alert: {e}")

    def prune(self, now: float):
        cutoff = now - 900  # Keep 15m window
        for dq in self.event_timestamps.values():
            while dq and dq[0] < cutoff:
                dq.popleft()
        for dq in self.instance_total_timestamps.values():
            while dq and dq[0] < cutoff:
                dq.popleft()
        for dq in self.instance_unstructured_timestamps.values():
            while dq and dq[0] < cutoff:
                dq.popleft()

    async def check_anomalies(self):
        now = time.time()
        uptime = now - self.start_time
        queue_size = self.pg_sink.queue.qsize() if self.pg_sink else 0

        # Check arming transition:
        # 1. Minimum warmup duration elapsed (default 15m)
        # 2. Ingestion backlog flushed & settled (queue < 500)
        if not self.is_armed:
            if uptime >= self.warmup_seconds and queue_size < 500:
                self.is_armed = True
                self.armed_at = now
                print(f"[AnomalyDetector] Baseline stabilized after {uptime:.1f}s. System ARMED for alerts.")
                try:
                    from alert import dispatch_discord_alert
                    asyncio.create_task(dispatch_discord_alert(
                        title="LogNode Baseline Stabilized & Armed",
                        description=f"Fleet telemetry baseline calibrated across {self.warmup_seconds//60}m window. Anomaly alarms and alert-of-last-resort are now active.",
                        severity="info",
                        instance="hub",
                        event="baseline_armed",
                        spike_info="System Armed",
                        force=True
                    ))
                except Exception as e:
                    print(f"[AnomalyDetector] Failed to dispatch arming notice: {e}")

        # If system is in massive backlog catchup/drain mode, hold evaluation
        if queue_size >= 1000:
            return

        self.prune(now)
        cutoff_1m = now - 60
        window_mins = min(max(uptime / 60.0, 1.0), 15.0)

        try:
            from alert import dispatch_discord_alert
        except ImportError:
            dispatch_discord_alert = None

        # 1. Check Rate Spikes (4-sigma & >= 2.5x baseline)
        for (instance, event), dq in list(self.event_timestamps.items()):
            if not dq:
                continue

            # Check time-bucket diversity: must have appeared in at least 5 distinct minute buckets
            minute_buckets = set(int(t // 60) for t in dq)
            if len(minute_buckets) < 5:
                continue

            count_1m = sum(1 for t in dq if t >= cutoff_1m)
            total_window = len(dq)

            avg_1m = total_window / window_mins
            std_1m = max(math.sqrt(avg_1m), 1.0)
            z_score = (count_1m - avg_1m) / std_1m

            # Strict threshold: at least 30 logs/min, z-score >= 4.0, and 2.5x average
            if count_1m >= 30 and z_score >= 4.0 and count_1m >= (avg_1m * 2.5):
                spike_desc = f"{count_1m}/min vs {avg_1m:.1f}/min baseline (+{z_score:.1f}σ)"
                self.active_anomalies[f"{instance}:{event}"] = {
                    "type": "rate_spike",
                    "instance": instance,
                    "event": event,
                    "z_score": round(z_score, 2),
                    "count_1m": count_1m,
                    "avg_1m": round(avg_1m, 1),
                    "armed": self.is_armed,
                    "timestamp": now
                }
                # ONLY dispatch external Discord alerts when baseline is ARMED
                if self.is_armed and dispatch_discord_alert:
                    asyncio.create_task(dispatch_discord_alert(
                        title=f"Rate Spike on {instance}",
                        description=f"Event `{event}` surged to {count_1m} logs/min ({z_score:.1f}σ above baseline).",
                        severity="warning",
                        instance=instance,
                        event=event,
                        spike_info=spike_desc
                    ))
            elif f"{instance}:{event}" in self.active_anomalies and z_score < 2.0:
                self.active_anomalies.pop(f"{instance}:{event}", None)

        # 2. Check Unstructured Error Surges (> 20% of host volume)
        for instance, dq in list(self.instance_total_timestamps.items()):
            total_1m = sum(1 for t in dq if t >= cutoff_1m)
            if total_1m < 50:
                continue
            unstruct_dq = self.instance_unstructured_timestamps.get(instance, deque())
            unstruct_1m = sum(1 for t in unstruct_dq if t >= cutoff_1m)
            unstruct_ratio = (unstruct_1m / total_1m) * 100

            key = f"{instance}:unstructured_surge"
            if unstruct_ratio > 20.0 and unstruct_1m >= 20:
                self.active_anomalies[key] = {
                    "type": "unstructured_surge",
                    "instance": instance,
                    "event": "unstructured_surge",
                    "ratio": round(unstruct_ratio, 1),
                    "count_1m": unstruct_1m,
                    "total_1m": total_1m,
                    "armed": self.is_armed,
                    "timestamp": now
                }
                # ONLY dispatch external Discord alerts when baseline is ARMED
                if self.is_armed and dispatch_discord_alert:
                    asyncio.create_task(dispatch_discord_alert(
                        title=f"Unstructured Log Surge on {instance}",
                        description=f"{unstruct_ratio:.1f}% of incoming logs on `{instance}` are unrecognized ({unstruct_1m}/{total_1m} in last minute). Potential novel exception storm.",
                        severity="warning",
                        instance=instance,
                        event="unstructured_surge",
                        spike_info=f"{unstruct_ratio:.1f}% unrecognized"
                    ))
            elif key in self.active_anomalies and unstruct_ratio < 8.0:
                self.active_anomalies.pop(key, None)

    async def _loop(self):
        while self._running:
            try:
                await self.check_anomalies()
            except Exception as e:
                print(f"[AnomalyDetector] Error in loop: {e}")
            await asyncio.sleep(self.check_interval)

    def start(self):
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop())

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()


class AsyncLogPipeline:
    def __init__(self, model: str = DEFAULT_MODEL, events_file: Path = EVENTS_LOG_FILE):
        self.matcher = HotPathMatcher()
        self.clusterer = SkeletonClusterer(cluster_threshold=3)
        self.templatizer = OllamaTemplatizer(model=model)
        self.events_file = events_file
        self.pg = PostgresSink()
        self.anomaly_detector = AnomalyDetector()
        self.anomaly_detector.pg_sink = self.pg
        self.graph = TrafficGraph()
        self.graph.anomaly_detector = self.anomaly_detector
        self.pg.on_flush = lambda count: self.graph.record_internal_metric(
            source="hub:lognode",
            target="hub:postgres",
            protocol="internal",
            channel="db_flush",
            count=count
        )
        # Concurrency is a knob because the right value depends on the backend:
        # 2 for an Ollama sharing this box's cores, more for a router fronting
        # remote models. It is NOT the fix for a slow drain -- see the backoff.
        self._synthesis_sem = asyncio.Semaphore(SYNTH_CONCURRENCY)
        self._in_flight_skeletons = set()
        self._synth_backoff: Dict[str, Tuple[float, int]] = {}   # skel -> (retry_at, failures)
        self.stats = {
            "total_ingested": 0,
            "hot_path_matches": 0,
            "cold_path_buffered": 0,
            "templates_synthesized": 0,
            # Counted separately so the first number can be believed. It used
            # to include every rule add_rule rejected -- 97.5% of them.
            "templates_rejected": 0,
            "synthesis_skipped_backoff": 0
        }

    async def start(self):
        await self.pg.start()
        self.anomaly_detector.start()
        self.graph.start()

    async def close(self):
        self.graph.stop()
        self.anomaly_detector.stop()
        await self.pg.close()

    def _append_event(self, record: Dict[str, Any]):
        pass

    async def _async_synthesize_and_promote(self, skel: str, samples: List[str]):
        if synth_should_skip(skel, self._synth_backoff, time.time()):
            self.stats["synthesis_skipped_backoff"] += 1
            return
        if skel in self._in_flight_skeletons:
            return
        self._in_flight_skeletons.add(skel)
        async with self._synthesis_sem:
            try:
                self.graph.record_internal_metric(
                    source="hub:lognode",
                    target="hub:ollama",
                    protocol="http",
                    channel="llm_synthesis",
                    count=1
                )
                print(f"\n[AsyncWorker] Synthesizing rule for skeleton: {skel[:60]}...")
                rule = await self.templatizer.synthesize_async(samples)
                if not rule:
                    print(f"[AsyncWorker] LLM synthesis rejected/failed. Engaging deterministic skeleton fallback...")
                    rule = self.templatizer.synthesize_from_skeleton(skel, samples)
                added = bool(rule) and self.matcher.add_rule(rule)
                if added:
                    self.stats["templates_synthesized"] += 1
                    self._synth_backoff.pop(skel, None)
                else:
                    self.stats["templates_rejected"] += 1
                    failures = self._synth_backoff.get(skel, (0.0, 0))[1] + 1
                    wait = synth_backoff_seconds(failures)
                    self._synth_backoff[skel] = (time.time() + wait, failures)
                    print(f"[AsyncWorker] Not promoted ({'rejected by add_rule' if rule else 'no rule produced'}); "
                          f"backing off {wait:.0f}s, failure #{failures}: {skel[:60]}...")
                    if len(self._synth_backoff) > 5000:
                        now = time.time()
                        self._synth_backoff = {k: v for k, v in self._synth_backoff.items() if v[0] > now}
            finally:
                self._in_flight_skeletons.discard(skel)

    async def _maybe_alert_unit_failure(self, line: str, labels: Dict[str, str]):
        """Alert on a failed systemd unit reported by the unitwatch collector.

        Deliberately a RULE, not an anomaly. Everything else LogNode alerts on is
        statistical -- a rate spike against a baseline -- and a failed unit is
        exactly the shape that defeats that: one line, once, possibly the only
        one all week. certbot.service failed twice a day for two months in full
        view of this pipeline because nothing was looking for it by name.

        Keyed per (instance, unit) so one broken unit does not mask another on
        the same host, and so a persistently failed unit alerts once rather than
        every time the collector runs.
        """
        if "unitwatch " not in line or "active=failed" not in line:
            return
        try:
            fields = dict(
                part.split("=", 1) for part in line.split() if "=" in part
            )
        except Exception:
            return

        unit = fields.get("unit")
        if not unit:
            return
        instance = fields.get("instance") or labels.get("instance") or "unknown"

        if _dispatch_alert is None:
            return

        # Dedup deliberately does NOT use the dispatcher's should_alert(). Its
        # window is 300s and the collector sweeps every 300s, so a PERMANENTLY
        # failed unit would alert every five minutes for ever. The first real
        # find proved the point: cloud-final.service on app-server has
        # been failed since 2026-04-19. An alert that fires every five minutes
        # about a five-month-old condition gets muted, and a muted channel is
        # worse than no channel -- it is the certbot failure again, wearing a
        # different hat.
        #
        # So this rule owns its own dedup on a much longer window and forces the
        # dispatch past the short one.
        event = "unit_failed:" + unit
        key = instance + "|" + unit
        now = time.time()
        if (now - _unit_alert_last.get(key, 0.0)) < UNIT_ALERT_COOLDOWN:
            return
        _unit_alert_last[key] = now

        try:
            result = await _dispatch_alert(
                title="systemd unit failed: " + unit,
                description=(
                    "`%s` is in a failed state on **%s** (scope=%s, result=%s).\n"
                    "Reported by the unitwatch collector."
                    % (unit, instance, fields.get("scope", "?"), fields.get("result", "?"))
                ),
                severity="critical",
                instance=instance,
                event=event,
                spike_info="unit failure",
                kv={k: v for k, v in fields.items() if k != "unitwatch"},
                force=True,   # this rule owns dedup; see the note above
            )
            # Say what happened. An alerting path that is silent on success is
            # indistinguishable from one that is broken -- which is precisely
            # the bug that cost two months of expired certificate. The
            # "[UnitWatch]" prefix is capital-W and carries no "unitwatch "
            # token, so this line can never re-trigger the rule that emitted it.
            print("[UnitWatch] %s alert for %s on %s"
                  % ((result or {}).get("status", "unknown"), unit, instance))
        except Exception as exc:
            print("[UnitWatch] failed to dispatch alert for %s: %s" % (unit, exc))

    @staticmethod
    def _is_internal_noise(line: str, labels: Dict[str, Any]) -> bool:
        """LogNode's own chatter, which it would otherwise ingest forever.

        Extracted from ingest() so the structured path applies exactly the same
        rule. Two copies of this list would diverge, and the failure would be a
        self-amplifying feedback loop rather than a wrong answer -- LogNode
        ships its own journal to itself, so anything it prints comes back in.
        """
        if (labels.get("unit", "") in ("lognode.service", "ollama.service")
                or labels.get("user_unit", "") in ("lognode.service", "ollama.service")
                or labels.get("syslog_identifier", "") in ("ollama", "lognode")
                or labels.get("comm", "") in ("ollama", "llama-server")):
            return True
        if line.startswith((
                "[AsyncWorker]", "[Templatizer]", "[HotPath]", "[Postgres]",
                "[Network]", "[LokiPush]", "[GIN]", "[AnomalyDetector]", "[Graph]",
                # A UnitWatch line quoting the offending log line re-triggers the
                # rule that wrote it -- an observed, self-amplifying loop.
                "[UnitWatch]",
                "slot ", "srv ", "sampler params", "slot launch_slot_:")):
            return True
        if any(k in line for k in (
                "dry_multiplier =", "repeat_last_n =", "mirostat =", "top_k =",
                "n_ctx_slot =", "sampler chain:", "prompt cache update",
                "init sampler, took", "launch_slot_:", "task.n_tokens",
                "sampling params", "processing task")):
            return True
        return "com.apple.system.opendirectoryd" in line

    async def ingest_structured(self, mapped: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest an event whose structure already exists. From ecs.map_event.

        This deliberately skips the two most expensive things ingest() does, and
        the skip is the feature rather than an optimisation:

        - HotPathMatcher.match, a linear scan over ~1,400 compiled regexes. Its
          cost grows with the template count, and the template count grows with
          host diversity, so the matcher's ceiling FALLS as hosts are added.
          Bypassing it makes the per-line cost independent of fleet size.
        - SkeletonClusterer/the LLM templatizer. A miss here would cluster and,
          at three samples, fire a synthesis whose promotion path does a
          synchronous json.dump of the entire runtime template file on the event
          loop. Re-deriving structure that arrived already-derived would be a
          stability problem, not just wasted work.

        Everything that makes a log line useful to the rest of LogNode still
        runs: the noise filter, the anomaly detector, the traffic graph and the
        sink. An operator will notice /templates stop growing under Logstash
        traffic; that is intended, and the README says so.
        """
        raw = mapped.get("raw") or ""
        labels = mapped.get("labels") or {}
        if self._is_internal_noise(raw, labels):
            return {"status": "filtered"}

        self.stats["total_ingested"] += 1
        self.stats["structured_ingested"] = self.stats.get("structured_ingested", 0) + 1

        event = mapped.get("event") or "unstructured"
        kv = mapped.get("kv") or {}
        inst = labels.get("instance", "unknown")

        self.anomaly_detector.record_event(instance=inst, event=event, raw=raw, kv=kv)
        self.graph.observe_log(instance=inst, event=event, labels=labels, kv=kv,
                               raw=raw, byte_count=len(raw.encode("utf-8")))
        await self.pg.enqueue(event=event, kv=kv, raw=raw, labels=labels,
                              latency_us=0.0, ts=mapped.get("ts"))
        return {"status": "structured", "event": event}

    async def ingest(self, line: str, extra_labels: Optional[Dict[str, str]] = None,
                     ts: Optional[float] = None) -> Dict[str, Any]:
        """`ts` is the line's own time, if the shipper supplied one.

        Loki push carries a timestamp per entry, and an Alloy restart replays up
        to twelve hours of journal in a few minutes. Without this every replayed
        line was stamped with the minute it arrived, which is the misdating that
        turned 486 backfilled lines into one apparent burst. The same asymmetric
        clamp as the ECS path: the future is refused, age is kept.
        """
        if ts is not None:
            ts, suspect = ecs.clamp_ts(ts)
            if suspect is not None:
                self.stats["ts_clamped"] = self.stats.get("ts_clamped", 0) + 1
        line = line.strip()
        if not line:
            return {"status": "empty"}

        labels = extra_labels or {}
        if self._is_internal_noise(line, labels):
            return {"status": "filtered", "reason": "internal_telemetry_loop"}

        self.stats["total_ingested"] += 1

        # Every transport -- HTTP text, JSON, and the Loki protobuf path -- funnels
        # through here, so one hook covers them all.
        if "unitwatch " in line:
            # Fire-and-forget, NOT awaited. dispatch_discord_alert does global
            # rate limiting and a network round-trip to Discord; awaiting it
            # here put that latency directly in the ingest path, and when
            # unitwatch started reporting failures fleet-wide the accept queue
            # backed up to 104 pending connections and LogNode stopped serving.
            # The existing anomaly alerts in this file already use create_task
            # for exactly this reason; this one should have from the start.
            asyncio.create_task(self._maybe_alert_unit_failure(line, labels))
        inst = (extra_labels or {}).get("instance", "unknown")
        byte_len = len(line.encode("utf-8"))

        # 1. Hot Path: Try fast compiled regex match
        t0 = time.perf_counter()
        match_result = self.matcher.match(line)
        t_match_us = (time.perf_counter() - t0) * 1_000_000

        if match_result:
            self.stats["hot_path_matches"] += 1
            event, kv = match_result
            # Canonical field naming. The model picks capture-group names, so the
            # same value arrives as ip / addr / client / remote_addr across
            # templates, which is why graph.observe_log has to guess with chains
            # like kv.get("ip") or kv.get("client"). Normalising here means
            # Postgres, the anomaly detector and the graph all see one spelling.
            kv = normalize_fields(kv)
            record = {
                "timestamp": time.time(),
                "event": event,
                "kv": kv,
                "latency_us": round(t_match_us, 2),
                "labels": extra_labels or {},
                "raw": line
            }
            self._append_event(record)
            self.anomaly_detector.record_event(instance=inst, event=event, raw=line, kv=kv)
            self.graph.observe_log(instance=inst, event=event, labels=extra_labels, kv=kv, raw=line, byte_count=byte_len)
            await self.pg.enqueue(
                event=event,
                kv=kv,
                raw=line,
                labels=extra_labels,
                latency_us=round(t_match_us, 2),
                ts=ts
            )
            return {
                "status": "matched",
                "event": event,
                "kv": kv,
                "latency_us": round(t_match_us, 2)
            }

        # 2. Cold Path: Buffer unrecognized line & persist to Postgres
        self.stats["cold_path_buffered"] += 1
        record = {
            "timestamp": time.time(),
            "event": "unstructured",
            "kv": {},
            "latency_us": round(t_match_us, 2),
            "labels": extra_labels or {},
            "raw": line
        }
        self._append_event(record)
        self.anomaly_detector.record_event(instance=inst, event="unstructured", raw=line, kv={})
        self.graph.observe_log(instance=inst, event="unstructured", labels=extra_labels, kv={}, raw=line, byte_count=byte_len)
        await self.pg.enqueue(
            event="unstructured",
            kv={},
            raw=line,
            labels=extra_labels,
            latency_us=round(t_match_us, 2),
            ts=ts
        )

        cluster_ready = self.clusterer.add(line)
        if cluster_ready:
            skel, samples = cluster_ready
            asyncio.create_task(self._async_synthesize_and_promote(skel, samples))

        return {
            "status": "buffered",
            "raw": line
        }

