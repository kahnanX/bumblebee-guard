"""Tool schemas — what the LLM sees."""

BUMBLEBEE_GUARD_SCAN = {
    "name": "bumblebee_guard_scan",
    "description": (
        "Run a supply-chain scan of installed packages, MCP configs and editor/browser "
        "extensions via the local Bumblebee bridge. Exact-matches every (ecosystem, name, "
        "version) against curated catalogs of known-compromised packages, plus optional "
        "OSV.dev advisory matching. Use when the user asks whether the system is clean, "
        "after installing new packages/plugins, or when a supply-chain advisory drops. "
        "Read-only, runs as the current user, no sudo. May take 1-4 minutes."
    ),
    "parameters": {"type": "object", "properties": {}, "required": []},
}

BUMBLEBEE_GUARD_STATUS = {
    "name": "bumblebee_guard_status",
    "description": (
        "Report the latest Bumblebee supply-chain scan results without re-scanning: "
        "curated findings total, new-since-last, OSV advisory count, packages inventoried, "
        "catalogs loaded, last scan time. Use for a quick security status check."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "include_osv_preview": {
                "type": "boolean",
                "description": "Include the first few OSV advisory matches (default false).",
            },
        },
        "required": [],
    },
}

BUMBLEBEE_GUARD_DIFF = {
    "name": "bumblebee_guard_diff",
    "description": (
        "Diff curated known-malicious findings between the stored baseline and the latest "
        "scan (which packages appeared/disappeared), or set the current state as the new "
        "baseline. Read-only except for the baseline file inside the plugin's own data dir."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["show", "set_baseline"],
                "description": "show = compare latest scan vs baseline (default); set_baseline = store current scan as baseline.",
            },
        },
        "required": [],
    },
}

ALL_SCHEMAS = [BUMBLEBEE_GUARD_SCAN, BUMBLEBEE_GUARD_STATUS, BUMBLEBEE_GUARD_DIFF]
