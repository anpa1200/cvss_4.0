# CVSS v4.0 Enrichment Assistant — Heuristic Prioritization Prototype

> **Scope disclaimer:** This tool produces **heuristic priority estimates**, not authoritative CVSS-BTE scores. Score adjustments use empirical point-delta approximations, not the official CVSS v4.0 lookup tables. For authoritative CVSS-BTE scores use the [FIRST.org CVSS v4.0 calculator](https://www.first.org/cvss/calculator/4-0) with the vector strings this tool produces. This is not official FIRST.org tooling.

A command-line tool that takes CVE IDs and enriches them with live threat intelligence from CISA KEV, EPSS, and NVD. The output is a ranked report with heuristic priority estimates and actionable SLA recommendations — a starting point for triage, not a final answer.

**The problem it solves:** Scanner outputs show 9.8 Critical for every CVE, regardless of whether it has a known exploit, whether your systems are internet-accessible, or whether the affected component even holds sensitive data. This tool applies the CVSS v4.0 three-layer model (Base → Threat → Environmental) to that list, revealing which findings actually need immediate action and which can wait.

---

## ⚠ Important Limitations

| Limitation | Details |
|-----------|---------|
| **Heuristic scoring** | Priority estimates use empirical point-delta adjustments (E:U −3.0, MAV:A −2.0, MAC:H −1.0), not the official CVSS v4.0 lookup tables. Results will differ from the FIRST.org calculator. |
| **EPSS is a triage signal** | EPSS does not prove a PoC exists. High EPSS flags a CVE for manual verification — it does not automatically set E:P or E:A. Only CISA KEV entry confirms active exploitation (E:A). |
| **NVD v4.0 coverage gap** | Many CVEs — including widely-known ones like CVE-2021-44228, CVE-2023-4966, and CVE-2025-32433 — have only CVSS v3.1 vectors in NVD. The tool flags these and applies heuristic adjustment, but results are especially approximate. Re-score using the FIRST.org calculator. |
| **Not a replacement for assessment** | Environmental metrics are defaults from the selected profile. They may not reflect your specific network topology, compensating controls, or data classification. Verify important findings. |

For methodology details see [METHODOLOGY.md](METHODOLOGY.md).

> 📖 **Full methodology, worked examples, and field guide:** [CVSS v4.0: The Practical Field Guide for Vulnerability Management](https://medium.com/bugbountywriteup/cvss-v4-0-the-practical-field-guide-for-vulnerability-management-5b5a59728456)

---

## How It Works

```
CVE IDs → NVD API (Base vector)
        → CISA KEV (E:A if listed)
        → EPSS API (triage signal; flags CVEs for manual PoC check)
        → Apply asset profile (MAV/MAC/CR/IR/AR/MSC...)
        → Heuristic priority estimate + enriched vector string
```

| Data Source | What It Provides | How It's Used |
|-------------|-----------------|---------------|
| **NVD API** | CVSS Base vector + base score | Starting point; flags when only v3.1 is available |
| **CISA KEV** | Confirmed active exploitation | Sets `E:A` (the only automatic E: assignment) |
| **FIRST.org EPSS** | Exploitation probability 0–1 | Triage flag only; EPSS ≥ 0.1 → manual PoC check needed |

### Exploit Maturity (E:) Decision Logic

```
Is CVE in CISA KEV catalog?
  → YES  →  E:A  (confirmed active exploitation — automatic)

Is EPSS ≥ 0.1?
  → YES  →  E:U  (conservative default) + ⚠ VERIFY flag
            Manually check: ExploitDB / Metasploit / vendor advisory
            If public PoC confirmed → upgrade to E:P in your tracker
            If active exploitation confirmed → upgrade to E:A

Otherwise:
  → E:U  (no exploitation evidence found)
```

**E:P is never set automatically.** Per the CVSS v4.0 specification, E:P requires confirmed availability of a public proof-of-concept exploit. EPSS is a probabilistic triage signal — a high EPSS score means exploitation is statistically likely, not that a PoC has been observed. The analyst must verify.

---

## Quick Start

```bash
# Install dependency
pip3 install requests

# Check a single CVE
python3 cvss_enrichment_tool.py --cves CVE-2021-44228

# Check multiple CVEs against an internet-facing profile
python3 cvss_enrichment_tool.py \
  --cves CVE-2023-4966 CVE-2023-34362 CVE-2024-21762 \
  --profile internet_facing

# Batch mode from file + save CSV report
python3 cvss_enrichment_tool.py \
  --file cves.txt \
  --profile internal_vlan \
  --output report.csv \
  --verbose

# See all built-in profiles
python3 cvss_enrichment_tool.py --list-profiles
```

---

## Usage

```
usage: cvss_enrichment_tool.py [-h]
  [--cves CVE-ID [CVE-ID ...]]
  [--file PATH]
  [--profile {internet_facing,internal_vlan,isolated_ot,dev_test,healthcare_ehr,pci_payment}]
  [--output PATH]
  [--json PATH]
  [--apikey KEY]
  [--list-profiles]
  [--verbose]
```

| Flag | Description |
|------|-------------|
| `--cves` | One or more CVE IDs inline |
| `--file` | Path to a text file with one CVE ID per line (lines starting with `#` are ignored) |
| `--profile` | Asset profile for environmental metrics (default: `internal_vlan`) |
| `--output` | Write results to CSV |
| `--json` | Write results to JSON |
| `--apikey` | NVD API key (free registration — raises rate limit from 5 to 50 req/30s) |
| `--list-profiles` | Print all built-in profiles and exit |
| `--verbose` | Print progress messages |

---

## Asset Profiles

Profiles encode your network and data context as CVSS Environmental metrics. Instead of adjusting every CVE individually, you define the profile once and apply it to all CVEs on that asset group.

```bash
python3 cvss_enrichment_tool.py --list-profiles
```

| Profile | Name | Environmental Metrics Applied |
|---------|------|-------------------------------|
| `internet_facing` | Internet-Facing Services | `CR:H / IR:H / AR:H` |
| `internal_vlan` | Internal VLAN Systems | `MAV:A / MAC:H / CR:M / IR:M / AR:M` |
| `isolated_ot` | OT/ICS Isolated Network | `MAV:A / MAC:H / CR:L / IR:H / AR:H / MSC:N / MSI:N / MSA:N` |
| `dev_test` | Development / Test Environment | `MAV:L / CR:L / IR:L / AR:L` |
| `healthcare_ehr` | Healthcare EHR / PHI System | `CR:H / IR:H / AR:H` |
| `pci_payment` | PCI-DSS Payment Processing | `CR:H / IR:H / AR:H` |

**What the metrics mean:**

| Metric | What you are asserting |
|--------|------------------------|
| `MAV:A` | System is not internet-accessible — attacker must be on adjacent network |
| `MAC:H` | Access requires bypassing compensating controls (MFA, VPN, jump host) |
| `MSC:N / MSI:N / MSA:N` | System is isolated — no subsequent systems affected if compromised |
| `CR:H / IR:H / AR:H` | CIA is more important here than baseline — score increases |
| `CR:L / IR:L / AR:L` | CIA is less important here — test/dev context — score decreases |

Each environmental claim requires documented evidence in your tracking system. The tool produces enriched vector strings that you can attach to tickets; the evidence behind each metric is your responsibility.

---

## Live Test Output

Running the same 5 CVEs across two profiles shows the impact of environmental context:

**`internet_facing` profile — no network reduction:**

```
CVSS v4.0 Enrichment Assistant — Heuristic Prioritization Prototype
  ⚠ Priority estimates are approximate — not authoritative CVSS-BTE scores
  CVEs:    5
  Profile: Internet-Facing Services
  NVD key: none (5 req/30s limit)

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
CVE                    CVSS    KEV    EPSS    E:     NVD Sev     → Priority    SLA               Flags
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
CVE-2021-44228          3.1    YES  0.9446   E:A    Critical    → Critical    24–72 hours       v3.1→re-score
CVE-2023-4966           3.1    YES  0.9435   E:A    Critical    → Critical    24–72 hours       v3.1→re-score
CVE-2023-34362          3.1    YES  0.9437   E:A    Critical    → Critical    24–72 hours       v3.1→re-score
CVE-2024-21762          3.1    YES  0.9308   E:A    Critical    → Critical    24–72 hours       v3.1→re-score
CVE-2025-32433          3.1    YES  0.5031   E:A    Critical    → Critical    24–72 hours       v3.1→re-score
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  NVD Sev    = Severity from NVD base score (before any enrichment)
  → Priority = Heuristic estimate after E: and profile adjustments
  ⚠          = EPSS ≥ 0.1: manually verify PoC before treating as E:U final
  VERIFY PoC = Check ExploitDB/Metasploit/GitHub; upgrade E: if PoC found
  v3.1→re-score = NVD has v3.1 only; env. adjustment is approximate

  ⚠ Priority column is HEURISTIC — not authoritative CVSS-BTE scoring.
  Verify important findings at: https://www.first.org/cvss/calculator/4-0

Heuristic summary: 5 Critical  0 High  0 Medium  0 Low
```

**Same CVEs, `internal_vlan` profile (MAV:A + MAC:H applied):**

```
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
CVE                    CVSS    KEV    EPSS    E:     NVD Sev     → Priority    SLA               Flags
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
CVE-2021-44228          3.1    YES  0.9446   E:A    Critical    → High        30 days           v3.1→re-score
CVE-2023-4966           3.1    YES  0.9435   E:A    Critical    → High        30 days           v3.1→re-score
CVE-2023-34362          3.1    YES  0.9437   E:A    Critical    → High        30 days           v3.1→re-score
CVE-2024-21762          3.1    YES  0.9308   E:A    Critical    → High        30 days           v3.1→re-score
CVE-2025-32433          3.1    YES  0.5031   E:A    Critical    → Medium      90 days           v3.1→re-score
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Heuristic summary: 0 Critical  4 High  1 Medium  0 Low
```

The `NVD Sev` column shows severity before any enrichment. The `→ Priority` column shows the heuristic estimate after applying E: and profile adjustments. These are **two different things** — the tool makes that distinction visible.

> **Note on CVSS version column:** NVD publishes CVSS v4.0 vectors only for CVEs it has scored under v4.0. Many CVEs — including all five in the example above — return only v3.1 vectors from NVD as of this writing. The `v3.1→re-score` flag in the output indicates that environmental adjustments were applied to a v3.1 base as a heuristic only; verify at the FIRST.org calculator for authoritative results.

---

## Output Fields (CSV / JSON)

| Field | Description |
|-------|-------------|
| `cve` | CVE identifier |
| `cvss_version` | CVSS version of the base vector returned by NVD (`4.0` or `3.1`) |
| `base_vector` | Raw vector string from NVD |
| `base_score` | NVD Base score (numeric) |
| `base_severity` | Severity from NVD base score — **before any enrichment** |
| `in_kev` | `True` if CVE is in CISA KEV catalog |
| `kev_due_date` | KEV remediation due date (federal agencies) |
| `epss` | EPSS probability score (0.0–1.0) |
| `epss_verify` | `True` if EPSS ≥ 0.1 — manual PoC verification recommended |
| `exploit_maturity` | E metric assigned: `E:A`, `E:P`, or `E:U` |
| `exploit_rationale` | Human-readable source for the E determination |
| `asset_profile` | Profile name applied |
| `enriched_vector` | Base + Threat (+ Environmental) vector string |
| `heuristic_priority` | Approximate priority after enrichment: Critical / High / Medium / Low |
| `recommended_sla` | Suggested remediation timeline based on heuristic priority |
| `notes` | Warnings and manual action items (v3.1 flag, EPSS verify flag, etc.) |

---

## Heuristic Priority Tiers

| Heuristic Priority | Recommended SLA | Example Trigger |
|-------------------|----------------|----------------|
| Critical (≥ 9.0) | 24–72 hours | KEV entry + internet-facing + unauthenticated RCE |
| High (7.0–8.9) | 30 days | KEV + internal, or PoC + internet-facing |
| Medium (4.0–6.9) | 90 days | Internal + compensating controls + limited exploit evidence |
| Low (0.1–3.9) | Next release | Air-gapped, CR/IR/AR:L, no exploit evidence |

> These tiers are heuristic guidance. Verify important findings with the FIRST.org calculator using the enriched vector strings in the output.

---

## Batch File Format

```
# cves.txt — one CVE ID per line, lines starting with # are ignored
CVE-2021-44228
CVE-2023-4966
CVE-2023-34362
CVE-2024-21762
CVE-2025-32433
```

```bash
python3 cvss_enrichment_tool.py --file cves.txt --profile isolated_ot --output ot_report.csv
```

---

## NVD API Key

Without a key, NVD rate-limits requests to **5 per 30 seconds**. For batches larger than ~20 CVEs, register a free key at `https://nvd.nist.gov/developers/request-an-api-key` and pass it with `--apikey`.

With a key, the limit increases to **50 requests per 30 seconds**.

---

## Requirements

- Python 3.8+
- `requests` library (`pip3 install requests`)
- Internet access to CISA, FIRST.org, and NVD APIs

No other dependencies. No local database. All data is fetched live at runtime.

---

## CVSS v4.0 Background

This tool implements the three-layer scoring model defined in the [CVSS v4.0 Consumer Implementation Guide](https://www.first.org/cvss/v4.0/implementation-guide):

- **CVSS-B** — Base score only (vendor assessment, from NVD)
- **CVSS-BT** — Base + Threat (adds Exploit Maturity from KEV/EPSS)
- **CVSS-BTE** — Base + Threat + Environmental (adds asset context)

Per the CVSS v4.0 User Guide: "The Base Score represents a reasonable worst-case impact across different environments." It is a starting point — not a deployment-specific risk score. Environmental metrics let you apply documented, auditable adjustments that reflect your actual network topology, compensating controls, and data classification. That is not gaming the system; it is using the system correctly.

Detailed explanation and worked examples: [CVSS v4.0: The Practical Field Guide for Vulnerability Management](https://medium.com/@1200km) (Medium, March 2026)

---

## Author

**Andrey Pautov** — CTI analyst, Medium [@1200km](https://medium.com/@1200km)

---

## License

MIT — see [LICENSE](LICENSE)

---

## References

- CVSS v4.0 Specification: https://www.first.org/cvss/v4-0/
- CVSS v4.0 Consumer Implementation Guide: https://www.first.org/cvss/v4.0/implementation-guide
- CVSS v4.0 User Guide: https://www.first.org/cvss/user-guide
- EPSS: https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
