#!/usr/bin/env python3
"""
LogNode Discord Alert Dispatcher
================================
Dispatches formatted incident alerts and anomaly notifications to Discord
as the alert-of-last-resort. Includes anti-spam rate limiting and deduplication.
"""

import os
import time
import json
import asyncio
from typing import Optional, Dict, Any

try:
    import aiohttp
except ImportError:
    aiohttp = None

import urllib.request

WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "300"))  # 5 min default

# Deduplication state: (instance, event) -> last_dispatched_timestamp
_cooldown_tracker: Dict[str, float] = {}
_alert_lock = asyncio.Lock()
_last_global_send = 0.0

def get_webhook_url() -> str:
    global WEBHOOK_URL
    if not WEBHOOK_URL:
        env_path = os.path.expanduser("~/.config/lognode/lognode.env")
        if os.path.exists(env_path):
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("DISCORD_WEBHOOK_URL="):
                            WEBHOOK_URL = line.split("=", 1)[1].strip()
                            break
            except Exception:
                pass
    return WEBHOOK_URL

def should_alert(instance: str, event: str) -> bool:
    """Checks if an alert for this instance + event should be dispatched or suppressed."""
    key = f"{instance}:{event}"
    now = time.time()
    last = _cooldown_tracker.get(key, 0.0)
    if now - last < COOLDOWN_SECONDS:
        return False
    _cooldown_tracker[key] = now
    return True

async def dispatch_discord_alert(
    title: str,
    description: str,
    severity: str = "warning",
    instance: Optional[str] = None,
    event: Optional[str] = None,
    spike_info: Optional[str] = None,
    kv: Optional[Dict[str, Any]] = None,
    raw_sample: Optional[str] = None,
    force: bool = False
) -> Dict[str, Any]:
    """
    Sends a formatted Discord webhook embed for a detected anomaly or incident.
    Enforces per-incident cooldown and global rate limiting.
    """
    global _last_global_send

    url = get_webhook_url()
    if not url:
        return {"status": "skipped", "reason": "No DISCORD_WEBHOOK_URL configured"}

    inst = instance or "fleet"
    ev = event or "system_alert"

    if not force and not should_alert(inst, ev):
        time_left = int(COOLDOWN_SECONDS - (time.time() - _cooldown_tracker.get(f"{inst}:{ev}", 0)))
        return {
            "status": "suppressed",
            "reason": f"Cooldown active for {inst}:{ev} ({time_left}s remaining)"
        }

    # Color code
    sev_upper = severity.upper()
    if sev_upper == "CRITICAL":
        color = 0xE02424  # Red
        badge = "🚨 [CRITICAL]"
    elif sev_upper == "WARNING":
        color = 0xF59E0B  # Amber
        badge = "⚠️ [WARNING]"
    else:
        color = 0x3B82F6  # Blue
        badge = "ℹ️ [INFO]"

    fields = [
        {"name": "Host / Instance", "value": f"`{inst}`", "inline": True},
        {"name": "Event Pattern", "value": f"`{ev}`", "inline": True},
    ]

    if spike_info:
        fields.append({"name": "Rate / Spike", "value": f"**{spike_info}**", "inline": True})

    if kv:
        kv_str = json.dumps(kv, indent=2, ensure_ascii=False)
        if len(kv_str) > 500:
            kv_str = kv_str[:497] + "..."
        fields.append({"name": "Extracted Culprit KV", "value": f"```json\n{kv_str}\n```", "inline": False})

    if raw_sample:
        raw_trunc = raw_sample[:500] + "..." if len(raw_sample) > 500 else raw_sample
        fields.append({"name": "Raw Log Sample", "value": f"```\n{raw_trunc}\n```", "inline": False})

    embed = {
        "title": f"{badge} {title}",
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {
            "text": f"LogNode Fleet Observability • {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
        }
    }

    payload = {
        "username": "LogNode Fleet Watcher",
        "avatar_url": "https://raw.githubusercontent.com/grafana/grafana/main/public/img/grafana_icon.svg",
        "embeds": [embed]
    }

    async with _alert_lock:
        now = time.time()
        elapsed = now - _last_global_send
        if elapsed < 2.5:
            await asyncio.sleep(2.5 - elapsed)

        try:
            if aiohttp:
                timeout = aiohttp.ClientTimeout(total=5)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(url, json=payload) as resp:
                        _last_global_send = time.time()
                        if resp.status in (200, 204):
                            return {"status": "delivered", "instance": inst, "event": ev}
                        else:
                            text = await resp.text()
                            print(f"[Alert] Discord webhook error HTTP {resp.status}: {text}")
                            return {"status": "error", "code": resp.status, "text": text}
            else:
                loop = asyncio.get_running_loop()
                req_data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=req_data,
                    headers={"Content-Type": "application/json", "User-Agent": "LogNode-Alert/1.0"},
                    method="POST"
                )
                await loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=5))
                _last_global_send = time.time()
                return {"status": "delivered", "instance": inst, "event": ev}
        except Exception as e:
            print(f"[Alert] Failed to dispatch Discord alert: {e}")
            return {"status": "error", "error": str(e)}


if __name__ == "__main__":
    async def _test():
        res = await dispatch_discord_alert(
            title="LogNode Alert Verification Probe",
            description="Automated heartbeat probe verifying the alert-of-last-resort pipeline from LogNode.",
            severity="info",
            instance="laptop",
            event="probe_check",
            spike_info="Nominal baseline (1/1)",
            kv={"probe_id": "42", "engine": "lognode", "transport": "discord_webhook"},
            raw_sample="2026-09-13 18:20:00 [LogNode] Verification probe initialized",
            force=True
        )
        print("Test alert result:", res)

    asyncio.run(_test())
