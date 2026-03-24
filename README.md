# CVSS v4.0 Enrichment Tool

A command-line tool that takes CVE IDs and produces **CVSS-BTE scores** — Base + Threat + Environmental — by pulling live data from CISA KEV, EPSS, and NVD in a single automated pipeline.

The tool solves the most common failure mode in vulnerability management: treating raw Base scores as final answers. A `9.8 Critical` on an air-gapped internal system with no known exploit is operationally different from the same CVE on an internet-facing server in the CISA KEV catalog. This tool makes that difference visible and documentable.

> 📖 **Full methodology, worked examples, and field guide:** [CVSS v4.0: The Practical Field Guide for Vulnerability Management](https://medium.com/bugbountywriteup/cvss-v4-0-the-practical-field-guide-for-vulnerability-management-5b5a59728456)

---

## How It Works

```
CVE IDs → NVD API (Base vector) → CISA KEV (E:A?) → EPSS API (E:P/E:U?)
        → Apply asset profile (MAV/MAC/CR/IR/AR/MSC...)
        → Output CVSS-BTE vector + severity band + SLA recommendation
```

Three data sources, one output:

| Source | What It Provides | Used For |
|--------|-----------------|----------|
| **NVD API** | CVSS Base vector | Starting point (vendor worst-case score) |
| **CISA KEV** | Confirmed exploitation status | Sets `E:A` when listed |
| **FIRST.org EPSS** | Exploitation probability (0–1) | Sets `E:P` when ≥ 0.1, `E:U` when < 0.1 |

---

## Quick Start

```bash
# Install dependency
pip3 install requests

# Check a single CVE (default profile: internal_vlan)
python3 cvss_enrichment_tool.py --cves CVE-2021-44228

# Check multiple CVEs against an internet-facing asset profile
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

| Metric | What you are saying |
|--------|---------------------|
| `MAV:A` | System is not internet-accessible — attacker must be on adjacent network |
| `MAC:H` | Access requires bypassing compensating controls (MFA, VPN, jump host) |
| `MSC:N / MSI:N / MSA:N` | System is isolated — no subsequent systems affected |
| `CR:H / IR:H / AR:H` | CIA is more critical here than the vendor assumed (score goes up) |
| `CR:L / IR:L / AR:L` | CIA is less critical here — test/dev context (score goes down) |

---

## Live Test Output

Running against 5 real CVEs on the `internal_vlan` profile:

```
CVSS v4.0 Enrichment Tool
  CVEs:    5
  Profile: Internal VLAN Systems
  NVD key: none (5 req/30s limit)

  Loaded 1,551 KEV entries
  Got scores for 5 CVEs

──────────────────────────────────────────────────────────────────────────────────
CVE                   CVSS   KEV     EPSS  E      Severity    SLA
──────────────────────────────────────────────────────────────────────────────────
CVE-2021-44228         3.1   YES   0.9446  E:A    Critical    24–72 hours
CVE-2023-4966          3.1   YES   0.9435  E:A    Critical    24–72 hours
CVE-2023-34362         3.1   YES   0.9437  E:A    Critical    24–72 hours
CVE-2024-21762         3.1   YES   0.9308  E:A    Critical    24–72 hours
CVE-2025-32433         3.1   YES   0.5031  E:A    Critical    24–72 hours
──────────────────────────────────────────────────────────────────────────────────
Summary: 5 Critical  0 High  0 Medium  0 Low
```

> **Note on CVSS version column:** NVD publishes CVSS v4.0 vectors only for CVEs scored after November 2023. Older CVEs return v3.1 vectors. When a v3.1 vector is detected, the tool applies threat-only enrichment and flags the CVE in the Notes column with instructions to re-score manually at the FIRST.org calculator.

---

## Output Fields (CSV / JSON)

| Field | Description |
|-------|-------------|
| `cve` | CVE identifier |
| `cvss_version` | CVSS version of the base vector returned by NVD (`4.0` or `3.1`) |
| `base_vector` | Raw vector string from NVD |
| `base_score` | NVD Base score (numeric) |
| `in_kev` | `True` if CVE is in CISA KEV catalog |
| `kev_due_date` | KEV remediation due date (federal agencies) |
| `epss` | EPSS probability score (0.0–1.0) |
| `exploit_maturity` | Determined E metric: `E:A`, `E:P`, or `E:U` |
| `exploit_rationale` | Human-readable source for the E determination |
| `asset_profile` | Profile name applied |
| `bte_vector` | Full CVSS-BTE vector string with all enrichments appended |
| `severity_band` | Approximate severity: Critical / High / Medium / Low |
| `recommended_sla` | Suggested remediation timeline based on severity band |
| `notes` | Warnings (e.g., v3.1 vector detected, manual re-scoring required) |

---

## Exploit Maturity Decision Logic

```
Is CVE in CISA KEV?
  → YES  →  E:A  (confirmed active exploitation)

Is EPSS ≥ 0.5?
  → YES  →  E:P  (high exploitation probability — verify vendor advisories)

Is EPSS ≥ 0.1?
  → YES  →  E:P  (moderate — verify ExploitDB / Metasploit / GitHub)

Otherwise:
  → E:U  (no exploitation evidence)
```

**Data sources checked automatically:**
- CISA KEV: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- EPSS: `https://api.first.org/data/v1/epss`
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0`

---

## Severity Bands and SLA Tiers

| Approximate CVSS-BTE | Severity | Recommended SLA |
|----------------------|----------|----------------|
| 9.0 – 10.0 | Critical | 24–72 hours |
| 7.0 – 8.9 | High | 30 days |
| 4.0 – 6.9 | Medium | 90 days |
| 0.1 – 3.9 | Low | Next release cycle |

> Score approximation: the tool estimates CVSS-BTE by applying empirical adjustments to the NVD Base score (`E:U` −3.0 pts, `MAV:A` −2.0 pts, `MAC:H` −1.0 pt). For precise scores, use the FIRST.org v4.0 calculator with the full BTE vector string.

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

- **CVSS-B** — Base score only (vendor, worst-case, from NVD)
- **CVSS-BT** — Base + Threat (adds Exploit Maturity from KEV/EPSS)
- **CVSS-BTE** — Base + Threat + Environmental (adds asset context)

The Base score assumes your system is internet-facing, unprotected, and processing your most sensitive data. For 95%+ of CVEs, this overestimates actual risk. CVSS-BTE corrects this by encoding what your team knows about the actual deployment.

Detailed explanation and worked examples: [CVSS v4.0: The Practical Field Guide for Vulnerability Management](https://medium.com/@1200km) (Medium, March 2026)

---

## Author

**Andrey Pautov** — CTI analyst, Medium [@1200km](https://medium.com/@1200km)

---

## References

- CVSS v4.0 Specification: https://www.first.org/cvss/v4-0/
- CVSS v4.0 Consumer Implementation Guide: https://www.first.org/cvss/v4.0/implementation-guide
- EPSS: https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- SSVC: https://www.cisa.gov/ssvc
