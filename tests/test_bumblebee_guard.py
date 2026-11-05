"""Tests for bumblebee-guard — stdlib + pytest, bridge mocked."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_DIR))

os.environ["BUMBLEBEE_GUARD_DATA_DIR"] = str(PLUGIN_DIR / "tests" / "_data")
os.environ["BUMBLEBEE_STATE_DIR"] = str(PLUGIN_DIR / "tests" / "_state")

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "bumblebee_guard", PLUGIN_DIR / "__init__.py",
    submodule_search_locations=[str(PLUGIN_DIR)])
bg = importlib.util.module_from_spec(_spec)
sys.modules["bumblebee_guard"] = bg
_spec.loader.exec_module(bg)
core = bg.core
tools = bg.tools


@pytest.fixture(autouse=True)
def clean_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("BUMBLEBEE_GUARD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BUMBLEBEE_STATE_DIR", str(tmp_path / "state"))
    (tmp_path / "state").mkdir(parents=True)
    yield


SUMMARY = {
    "scanner_version": "v0.1.1",
    "scan_time_utc": "2026-11-05T03:52:46Z",
    "duration_ms": 179977,
    "files_considered": 409975,
    "catalogs_loaded": 8,
    "packages_total": 10343,
    "ecosystems": {"npm": 9004, "pypi": 1336, "mcp": 3},
    "findings_total": 1,
    "findings_new_since_last": 1,
    "findings_preview": [{"ecosystem": "npm", "name": "colors", "version": "1.4.44",
                          "severity": "critical", "catalog": "mini-shai-hulud.json"}],
    "osv_findings_total": 454,
    "status": "complete",
}


def write_summary(tmp_path, summary=SUMMARY):
    d = Path(os.environ["BUMBLEBEE_STATE_DIR"])
    d.mkdir(parents=True, exist_ok=True)
    (d / "bumblebee-summary.json").write_text(json.dumps(summary))


class FakeCtx:
    def __init__(self, config=None):
        self._config = config or {}

    def get_config(self):
        return self._config


def test_inject_suppressed_when_clean(tmp_path):
    s = dict(SUMMARY, findings_total=0, findings_new_since_last=0, findings_preview=[])
    write_summary(tmp_path, s)
    assert bg._summary_line(s) is None


def test_inject_emitted_on_findings(tmp_path):
    write_summary(tmp_path)
    line = bg._summary_line(SUMMARY)
    assert line and "SUPPLY-CHAIN ALERT" in line and "1 known-malicious" in line


def test_injection_rate_limited(tmp_path):
    write_summary(tmp_path)
    ctx = FakeCtx()
    first = bg._pre_llm_call(session_id="s1", user_message="hi")
    assert first and "context" in first
    second = bg._pre_llm_call(session_id="s1", user_message="hi")
    assert second is None  # within the 1h window


def test_status_no_summary(tmp_path):
    out = json.loads(tools.bumblebee_guard_status({}, ctx=FakeCtx()))
    assert out["ok"] is False


def test_status_with_summary(tmp_path):
    write_summary(tmp_path)
    out = json.loads(tools.bumblebee_guard_status({}, ctx=FakeCtx()))
    assert out["ok"] is True
    assert out["findings_total"] == 1
    assert out["packages_total"] == 10343
    assert out["osv_findings_total"] == 454


def test_diff_requires_baseline(tmp_path):
    write_summary(tmp_path)
    out = json.loads(tools.bumblebee_guard_diff({"action": "show"}, ctx=FakeCtx()))
    assert out["ok"] is True and out["baseline"] is False


def test_set_baseline_and_diff(tmp_path):
    write_summary(tmp_path)
    out = json.loads(tools.bumblebee_guard_diff({"action": "set_baseline"}, ctx=FakeCtx()))
    assert out["baseline_set"] is True
    changed = dict(SUMMARY, findings_total=2,
                   findings_preview=SUMMARY["findings_preview"] + [
                       {"ecosystem": "pypi", "name": "evilpkg", "version": "9.9.9",
                        "severity": "high", "catalog": "x.json"}])
    write_summary(tmp_path, changed)
    out = json.loads(tools.bumblebee_guard_diff({"action": "show"}, ctx=FakeCtx()))
    assert out["baseline"] is True
    assert out["added"] == [["pypi", "evilpkg", "9.9.9"]]
    assert out["removed"] == []
    assert out["curated_findings_now"] == 2


def test_scan_bridge_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "bridge_installed", lambda cfg: False)
    out = json.loads(tools.bumblebee_guard_scan({}, ctx=FakeCtx({"bridge_dir": str(tmp_path)})))
    assert out["ok"] is False and "not deployed" in out["error"]


def test_scan_success(tmp_path, monkeypatch):
    write_summary(tmp_path)
    monkeypatch.setattr(core, "bridge_installed", lambda cfg: True)
    monkeypatch.setattr(core.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(0, 0, "", ""))
    out = json.loads(tools.bumblebee_guard_scan({}, ctx=FakeCtx()))
    assert out["ok"] is True and out["summary"]["packages_total"] == 10343


def test_scan_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "bridge_installed", lambda cfg: True)

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="scan", timeout=1)

    monkeypatch.setattr(core.subprocess, "run", boom)
    out = json.loads(tools.bumblebee_guard_scan({}, ctx=FakeCtx({"scan_timeout_s": 1})))
    assert out["ok"] is False and out["error"] == "scan timed out"


def test_manifest_matches_registrations():
    import yaml

    manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text())
    names = [s["name"] for s in schemas_all()]
    assert names == manifest["provides_tools"]
    assert "pre_llm_call" in manifest["provides_hooks"]


def schemas_all():
    from bumblebee_guard import schemas

    return schemas.ALL_SCHEMAS
