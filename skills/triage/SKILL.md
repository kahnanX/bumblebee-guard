---
name: bumblebee-guard-triage
description: Triage Bumblebee supply-chain findings with confidence and dedup rules.
---

# Bumblebee Guard Triage

How to interpret bumblebee-guard results.

## Finding classes

- `findings_total` — curated catalogs of KNOWN-COMPROMISED packages. Exact
  `(ecosystem, name, version)` match only. High confidence: recommend
  immediate investigation/removal, never auto-ignore.
- `osv_findings_total` — OSV.dev advisory matches (vulnerabilities, not
  confirmed malware). Deduplicate aliases (GHSA/PYSEC pointing at the same
  advisory) before counting distinct issues, and check version applicability
  before acting. Never run upgrades from an untriaged count.

## Known false-positive pattern

A scan can flag a package whose source tree contains scanner/threat-intel
strings (e.g. lines in `site/index` test fixtures). If the finding is a
match against a catalog entry but the package is your own scanner tooling,
review the file content before declaring compromise.

## Blind spots (state clearly, never silently)

Zero curated findings means clean against the loaded catalogs — NOT
intrusion-free or vulnerability-free. File contents are not scanned.
Bumblebee inventories metadata only.
