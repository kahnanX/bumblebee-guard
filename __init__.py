"""bumblebee-guard — supply-chain guard plugin for Hermes Agent.

Wraps the local Bumblebee scanner bridge (perplexityai/bumblebee) with tools,
a rate-limited pre_llm_call context injection, a /bumblebee slash command and
a bundled triage skill. Read-only: scans run as the current user, no sudo,
no network calls of its own (the bridge's OSV layer and optional catalog
refresh make their own disclosed network calls).
"""

import json
import logging
import time

from . import core, schemas, tools

logger = logging.getLogger(__name__)

_INJECT_INTERVAL_S = 3600  # rate limit: at most one injection per hour


def _summary_line(summary: dict) -> str | None:
    """One-line security note, or None when there is nothing to warn about."""
    total = summary.get("findings_total") or 0
    new = summary.get("findings_new_since_last") or 0
    if total <= 0:
        return None  # clean: never inject, keep context cost at zero
    msg = f"[bumblebee-guard] SUPPLY-CHAIN ALERT: {total} known-malicious package finding(s)"
    if new:
        msg += f" ({new} new since last scan)"
    prev = summary.get("findings_preview") or []
    if prev:
        f0 = prev[0]
        msg += f" — e.g. {f0.get('ecosystem')}/{f0.get('name')}@{f0.get('version')}"
    msg += ". Call bumblebee_guard_status before touching these packages."
    return msg


def _pre_llm_call(session_id=None, user_message=None, **kwargs):
    """Rate-limited context injection: only when curated findings exist."""
    try:
        config = {}
        summary = core.read_summary(config)
        if summary is None:
            return None
        line = _summary_line(summary)
        if line is None:
            return None
        data_dir = core.plugin_data_dir_guard()
        state = core.load_state(data_dir)
        now = time.time()
        if now - state.get("last_inject_ts", 0) < _INJECT_INTERVAL_S:
            return None
        state["last_inject_ts"] = now
        core.save_state(data_dir, state)
        return {"context": line}
    except Exception:
        logger.debug("bumblebee-guard pre_llm_call skipped", exc_info=True)
        return None  # fail open: never block a turn


def _handle_slash(ctx, raw_args: str) -> str:
    action = (raw_args or "").strip().split()
    sub = action[0] if action else "status"
    if sub == "scan":
        return tools.bumblebee_guard_scan({}, ctx=ctx)
    if sub == "diff":
        act = action[1] if len(action) > 1 else "show"
        return tools.bumblebee_guard_diff({"action": act}, ctx=ctx)
    if sub == "help":
        return "usage: /bumblebee [status|scan|diff [show|set_baseline]]"
    return tools.bumblebee_guard_status({}, ctx=ctx)


def register(ctx):
    for schema in schemas.ALL_SCHEMAS:
        handler = getattr(tools, schema["name"])
        ctx.register_tool(name=schema["name"], toolset="bumblebee-guard",
                          schema=schema, handler=handler)
    ctx.register_hook("pre_llm_call", _pre_llm_call)
    ctx.register_command("bumblebee", lambda raw: _handle_slash(ctx, raw),
                         description="Bumblebee supply-chain scan status/scan/diff")
    # Bundle the triage skill
    try:
        from pathlib import Path

        skill_md = Path(__file__).parent / "skills" / "triage" / "SKILL.md"
        if skill_md.exists():
            ctx.register_skill("triage", skill_md.read_text())
    except Exception:
        logger.debug("bumblebee-guard skill registration skipped", exc_info=True)
