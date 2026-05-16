# Changelog

All notable changes to this project are documented here.

## [2.0.0] — 2026-05-16

### Breaking changes
- **Renamed module docstring and CLI banner** to "CVSS v4.0 Enrichment Assistant — Heuristic Prioritization Prototype" — accurately reflects that outputs are heuristic estimates, not authoritative CVSS-BTE scores.
- **`severity_band` renamed to `heuristic_priority`** — return value is now clearly labeled as approximate throughout the codebase and output.
- **`build_bte_vector` renamed to `build_enriched_vector`** — removes the implication that output is an authoritative BTE vector.

### New features
- **`epss_verify` flag** on every result — `True` when EPSS ≥ 0.1. Triggers "VERIFY PoC" flag in output table and `epss_verify` field in CSV/JSON. Analysts should manually check ExploitDB/Metasploit/GitHub before upgrading E:.
- **`base_severity` field** — records NVD Base severity separately from heuristic priority. Output table now shows both `NVD Sev` (before enrichment) and `→ Priority` (after), making the distinction visible.
- **Environmental metrics applied to v3.1 base vectors** — previously skipped; now applied as heuristic with a `v3.1→re-score` flag in the output. This corrects the prior behavior where all CVEs with v3.1 NVD vectors showed the same priority regardless of profile.
- **Footer legend in table output** — explains each column and includes authoritative calculator link.

### Fixes
- **EPSS no longer sets E:P automatically.** Previous versions set E:P when EPSS ≥ 0.1, which contradicts the CVSS v4.0 specification. E:P requires confirmed PoC availability — a probabilistic score is not evidence. Fix: EPSS ≥ 0.1 now sets `epss_verify=True` and returns E:U pending manual verification.
- **Fixed output contradiction for internal_vlan profile** — all 5 example CVEs previously showed "Critical" even with internal_vlan profile applied (because environmental metrics were skipped for v3.1 vectors). Now correctly shows High/Medium after profile adjustment.

### Methodology documentation
- Added `METHODOLOGY.md` explaining all empirical adjustments, their approximate ranges, and their limitations.
- Added `LICENSE` (MIT).

---

## [1.0.0] — 2026-03-24

### Initial release
- Basic enrichment pipeline: NVD → KEV → EPSS → profile-based Environmental metrics
- Six built-in asset profiles
- CSV and JSON output
- `--list-profiles`, `--verbose`, `--apikey` flags
