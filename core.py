"""Core logic for bumblebee-guard: locate the bridge, run scans, read summaries."""

import json
import logging
import os
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_FILE = "state.json"
BASELINE_FILE = "baseline.json"
PLUGIN_NAME = "bumblebee-guard"


def plugin_data_dir_guard() -> Path:
    """Hermes-managed plugin data dir; falls back to a local state dir in tests."""
    try:
        from plugins.plugin_storage import plugin_data_dir

        return Path(plugin_data_dir(PLUGIN_NAME))
    except Exception:
        return Path(os.environ.get("BUMBLEBEE_GUARD_DATA_DIR")
                    or Path.home() / ".local/state/bumblebee-guard")


def _bridge_dir(config: dict) -> Path:
    return Path(os.path.expanduser(config.get("bridge_dir") or "~/.local/share/hermes-bumblebee-bridge"))


def bridge_installed(config: dict) -> bool:
    b = _bridge_dir(config)
    return (b / "bin" / "bumblebee").exists() and (b / "daily_scan.sh").exists()


def run_scan(config: dict) -> dict:
    """Run the bridge scan. Returns the normalized summary dict (or an error payload)."""
    b = _bridge_dir(config)
    script = b / "daily_scan.sh"
    if not bridge_installed(config):
        return {"ok": False, "error": "bumblebee bridge not deployed", "hint": "run the bridge install.sh"}
    timeout = int(config.get("scan_timeout_s") or 240)
    try:
        t0 = time.monotonic()
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "INSTALL_DIR": str(b)},
        )
        duration_ms = int((time.monotonic() - t0) * 1000)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "scan timed out", "timeout_s": timeout}
    if proc.returncode != 0:
        return {"ok": False, "error": "daily_scan.sh failed", "stderr_tail": proc.stderr[-500:]}
    state_dir = Path(os.environ.get("BUMBLEBEE_STATE_DIR") or Path.home() / ".local/state/hermes-bumblebee-bridge")
    summary_path = state_dir / "bumblebee-summary.json"
    try:
        summary = json.loads(summary_path.read_text())
    except FileNotFoundError:
        return {"ok": False, "error": "summary file missing after scan", "stderr_tail": proc.stderr[-500:]}
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"summary not valid JSON: {e}"}
    summary["scan_duration_ms"] = duration_ms
    return {"ok": True, "summary": summary}


def read_summary(config: dict) -> dict | None:
    state_dir = Path(os.environ.get("BUMBLEBEE_STATE_DIR") or Path.home() / ".local/state/hermes-bumblebee-bridge")
    p = state_dir / "bumblebee-summary.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        logger.warning("bumblebee summary unreadable JSON")
        return None


def catalog_stats(config: dict) -> dict:
    b = _bridge_dir(config) / "catalogs"
    files, total = [], 0
    if b.is_dir():
        for f in sorted(b.glob("*.json")):
            try:
                d = json.loads(f.read_text())
                n = len(d) if isinstance(d, list) else sum(
                    len(v) if isinstance(v, list) else 1 for v in d.values())
            except Exception:
                n = -1
            files.append({"file": f.name, "entries": n})
            total += max(n, 0)
    return {"count": len(files), "total_entries": total, "files": files}


def load_state(data_dir: Path) -> dict:
    p = data_dir / STATE_FILE
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            pass
    return {"last_inject_ts": 0.0, "last_summary_ts": None, "findings_seen": {}}


def save_state(data_dir: Path, state: dict) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = data_dir / (STATE_FILE + ".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    os.replace(tmp, data_dir / STATE_FILE)


def make_baseline(summary: dict) -> dict:
    return {
        "scan_time_utc": summary.get("scan_time_utc"),
        "findings_total": summary.get("findings_total", 0),
        "findings": summary.get("findings_preview", []),
        "packages_total": summary.get("packages_total"),
        "osv_findings_total": summary.get("osv_findings_total", 0),
    }


def diff_vs_baseline(summary: dict, baseline: dict | None) -> dict:
    """File-level delta of curated findings between the baseline snapshot and now."""
    if not baseline:
        return {"baseline": False,
                "note": "no baseline stored yet; call bumblebee_guard_diff with action=set_baseline"}
    now = make_baseline(summary)
    old = {(f.get("ecosystem"), f.get("name"), f.get("version")) for f in baseline.get("findings", [])}
    new = {(f.get("ecosystem"), f.get("name"), f.get("version")) for f in now.get("findings", [])}
    return {
        "baseline": True,
        "baseline_ts": baseline.get("scan_time_utc"),
        "current_ts": now.get("scan_time_utc"),
        "added": sorted(n for n in new - old),
        "removed": sorted(o for o in old - new),
        "curated_findings_before": baseline.get("findings_total"),
        "curated_findings_now": now.get("findings_total"),
        "packages_before": baseline.get("packages_total"),
        "packages_now": now.get("packages_total"),
    }
