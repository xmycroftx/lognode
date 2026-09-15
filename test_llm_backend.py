#!/usr/bin/env python3
"""Templatizer against both wire formats: Ollama native and OpenAI/LiteLLM.

Runs a mock router on localhost so the whole path is exercised -- payload shape,
auth header, response parsing -- rather than just the helpers.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import engine

ok = True
seen = {}


def check(label, cond):
    global ok
    print("  %-56s %s" % (label, "PASS" if cond else "FAIL"))
    if not cond:
        ok = False


REGEX = r"worker (?P<worker>\d+) finished in (?P<duration>\d+)ms"
ANSWER = json.dumps({"event": "worker_finished", "regex": REGEX})


class Mock(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        seen["path"] = self.path
        seen["payload"] = body
        seen["auth"] = self.headers.get("Authorization")
        if "chat/completions" in self.path:      # OpenAI / LiteLLM shape
            out = {"choices": [{"message": {"role": "assistant", "content": ANSWER}}]}
        else:                                     # Ollama native
            out = {"message": {"role": "assistant", "content": ANSWER}}
        raw = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), Mock)
port = srv.server_port
threading.Thread(target=srv.serve_forever, daemon=True).start()

SAMPLES = ["worker 1 finished in 42ms", "worker 2 finished in 51ms"]

# --- style detection --------------------------------------------------------
check("detects ollama from /api/chat",
      engine.detect_llm_style("http://x:11434/api/chat") == "ollama")
check("detects openai from /v1/chat/completions",
      engine.detect_llm_style("http://x:4000/v1/chat/completions") == "openai")
check("detects openai from a bare /v1 base",
      engine.detect_llm_style("https://api.example.com/v1") == "openai")
os.environ["LOGNODE_LLM_STYLE"] = "ollama"
check("LOGNODE_LLM_STYLE overrides detection",
      engine.detect_llm_style("http://x:4000/v1/chat/completions") == "ollama")
del os.environ["LOGNODE_LLM_STYLE"]

# --- Ollama path ------------------------------------------------------------
t = engine.OllamaTemplatizer(model="qwen2.5-coder:1.5b",
                             api_url="http://127.0.0.1:%d/api/chat" % port)
rule = t._call_ollama(SAMPLES)
check("ollama: returns a rule", rule is not None and rule.event == "worker_finished")
check("ollama: payload uses format=json", seen["payload"].get("format") == "json")
check("ollama: payload uses options.num_predict",
      (seen["payload"].get("options") or {}).get("num_predict") == 384)
check("ollama: no auth header when no key", seen["auth"] is None)

# --- LiteLLM / OpenAI path --------------------------------------------------
t2 = engine.OllamaTemplatizer(model="gpt-4o-mini",
                              api_url="http://127.0.0.1:%d/v1/chat/completions" % port,
                              api_key="test-key-123")
rule2 = t2._call_ollama(SAMPLES)
check("litellm: returns a rule", rule2 is not None and rule2.event == "worker_finished")
check("litellm: model passed through", seen["payload"].get("model") == "gpt-4o-mini")
check("litellm: uses max_tokens not options", "max_tokens" in seen["payload"]
      and "options" not in seen["payload"])
check("litellm: asks for json_object",
      (seen["payload"].get("response_format") or {}).get("type") == "json_object")
check("litellm: sends bearer token", seen["auth"] == "Bearer test-key-123")
check("litellm: messages carry system+user",
      [m["role"] for m in seen["payload"]["messages"]] == ["system", "user"])

# --- reasoning-model variants -----------------------------------------------
t3 = engine.OllamaTemplatizer(api_url="http://x/v1/chat/completions")
check("openai: falls back to reasoning_content",
      t3._extract_content({"choices": [{"message": {"content": "",
                                                    "reasoning_content": "X"}}]}) == "X")
t4 = engine.OllamaTemplatizer(api_url="http://x/api/chat")
check("ollama: falls back to reasoning",
      t4._extract_content({"message": {"content": "", "reasoning": "Y"}}) == "Y")
check("empty response is empty string, not a crash",
      t3._extract_content({}) == "" and t4._extract_content({}) == "")

srv.shutdown()
print("  ---", "ALL PASS" if ok else "FAILURES PRESENT")
raise SystemExit(0 if ok else 1)
