"""Tool handlers for bumblebee-guard. Every handler returns a JSON string."""

import json

from . import core

# Plugin settings are captured ONCE at register() time via ctx.get_config(key, default).
# Tool handlers and the pre_llm_call hook never receive ctx at call time, so per-call
# ctx.get_config() lookups silently no-op (upstream review 2026-11-05, point 3).
SETTINGS: dict = {}
_DEFAULTS = {
    "bridge_dir": "~/.local/share/hermes-bumblebee-bridge",
    "scan_timeout_s": 240,
    "osv_enabled": True,
    "inject_status": True,
}


def capture_settings(ctx) -> dict:
    """Read each settings key explicitly with ctx.get_config(key, default)."""
    for key, default in _DEFAULTS.items():
        try:
            SETTINGS[key] = ctx.get_config(key, default)
        except Exception:
            SETTINGS[key] = default
    return dict(SETTINGS)


def config() -> dict:
    """Effective settings for core.* calls."""
    return {k: SETTINGS.get(k, d) for k, d in _DEFAULTS.items()}


def bumblebee_guard_scan(args: dict, ctx=None, **kwargs) -> str:
    result = core.run_scan(config())
    data_dir = core.plugin_data_dir_guard()
    if result.get("ok"):
        summary = result["summary"]
        state = core.load_state(data_dir)
        state["last_summary_ts"] = summary.get("scan_time_utc")
        core.save_state(data_dir, state)
    return json.dumps(result)


def bumblebee_guard_status(args: dict, ctx=None, **kwargs) -> str:
    cfg = config()
    summary = core.read_summary(cfg)
    if summary is None:
        return json.dumps({"ok": False, "error": "no scan summary found — run bumblebee_guard_scan first",
                           "bridge_installed": core.bridge_installed(cfg)})
    out = {
        "ok": True,
        "scanner_version": summary.get("scanner_version"),
        "scan_time_utc": summary.get("scan_time_utc"),
        "status": summary.get("status"),
        "duration_ms": summary.get("duration_ms"),
        "files_considered": summary.get("files_considered"),
        "packages_total": summary.get("packages_total"),
        "ecosystems": summary.get("ecosystems"),
        "findings_total": summary.get("findings_total"),
        "findings_preview": summary.get("findings_preview", []),
        "findings_new_since_last": summary.get("findings_new_since_last"),
        "catalogs": core.catalog_stats(cfg),
    }
    if cfg.get("osv_enabled", True) and "osv_findings_total" in summary:
        out["osv_findings_total"] = summary.get("osv_findings_total")
        if args.get("include_osv_preview"):
            out["osv_preview"] = summary.get("osv_preview", [])[:5]
    return json.dumps(out)


def bumblebee_guard_diff(args: dict, ctx=None, **kwargs) -> str:
    data_dir = core.plugin_data_dir_guard()
    action = args.get("action", "show")
    summary = core.read_summary(config())
    if summary is None:
        return json.dumps({"ok": False, "error": "no scan summary found — run bumblebee_guard_scan first"})
    baseline_path = data_dir / core.BASELINE_FILE
    if action == "set_baseline":
        data_dir.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(core.make_baseline(summary), indent=1))
        return json.dumps({"ok": True, "baseline_set": True,
                           "scan_time_utc": summary.get("scan_time_utc"),
                           "curated_findings": summary.get("findings_total")})
    baseline = None
    if baseline_path.exists():
        try:
            baseline = json.loads(baseline_path.read_text())
        except json.JSONDecodeError:
            baseline = None
    return json.dumps({"ok": True, **core.diff_vs_baseline(summary, baseline)})
