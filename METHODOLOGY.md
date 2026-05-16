# Methodology: Heuristic Scoring Approach

This document describes how the tool approximates CVSS-BTE priority estimates and the limitations of each step.

---

## Why Heuristics?

The official CVSS v4.0 scoring algorithm uses lookup tables defined in the [CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/). These tables encode the interaction between dozens of metric combinations in a non-linear way — there is no formula. The FIRST.org [online calculator](https://www.first.org/cvss/calculator/4-0) implements these lookup tables correctly.

This tool uses **empirical point-delta approximations** instead — simpler adjustments that produce directionally correct results at the cost of precision. The goal is fast triage prioritization, not authoritative scoring.

---

## Step 1: Base Score (NVD)

The tool fetches the CVSS vector from NVD API 2.0. Preference order: CVSS v4.0 → CVSS v3.1.

**CVSS v4.0 coverage gap:** NVD only publishes CVSS v4.0 vectors for CVEs that have been formally assessed under v4.0. Many widely-known CVEs — including CVE-2021-44228, CVE-2023-4966, CVE-2023-34362, CVE-2024-21762, and CVE-2025-32433 — return only v3.1 vectors as of this writing. When a v3.1 vector is returned, the tool applies environmental heuristics to the v3.1 base score and flags the result with `v3.1→re-score`. This is especially approximate; re-score at the FIRST.org calculator.

---

## Step 2: Exploit Maturity (E:)

The E: metric is set from CONFIRMED evidence sources only:

| Source | E: Value | Notes |
|--------|---------|-------|
| CISA KEV catalog | `E:A` | Automatic — confirmed active exploitation |
| Manual analyst verification of PoC | `E:P` | Not set automatically — analyst must check ExploitDB/Metasploit |
| No evidence found | `E:U` | Conservative default |

**EPSS is a triage signal, not an evidence source.**

EPSS (Exploit Prediction Scoring System) estimates the probability that a CVE will be exploited in the next 30 days. A high EPSS score indicates statistical likelihood, not confirmed PoC availability. Per the CVSS v4.0 specification:

- `E:P` requires a public proof-of-concept to exist
- `E:A` requires confirmed attacks in the wild or exploit tooling

EPSS does not satisfy either requirement by itself. The tool uses EPSS thresholds only to flag CVEs for manual verification:

| EPSS Range | Action |
|-----------|--------|
| EPSS < 0.1 | E:U — no exploitation evidence; no flag |
| EPSS 0.1–0.5 | E:U — `epss_verify=True` → check ExploitDB/Metasploit |
| EPSS ≥ 0.5 | E:U — `epss_verify=True` → high priority manual check |

If that manual check finds a public PoC → analyst sets E:P in their tracking system.
If that manual check finds active exploitation → analyst sets E:A.

---

## Step 3: Heuristic Priority Calculation

The heuristic starts from the NVD base score and applies empirical point-delta adjustments.

### Empirical adjustments (observed from FIRST.org calculator)

| Metric | Heuristic Delta | Actual Range Observed |
|--------|----------------|----------------------|
| E:U | −3.0 | −2.5 to −3.5 |
| E:P | −1.2 | −1.0 to −1.5 |
| E:A | ±0 | ±0 (confirmed max-threat maintains score) |
| MAV:A | −2.0 | −1.5 to −2.5 |
| MAV:L | −3.0 | −2.5 to −3.5 |
| MAV:P | −4.0 | −3.5 to −4.5 |
| MAC:H | −1.0 | −0.5 to −1.5 |
| MSC:N | −0.4 | −0.3 to −0.8 |
| MSI:N | −0.2 | −0.1 to −0.5 |
| MSA:N | −0.2 | −0.1 to −0.5 |
| CR:H / IR:H / AR:H | +0.3 each | +0.3 to +0.8 |
| CR:L / IR:L / AR:L | −0.3 each | −0.3 to −0.8 |

Adjustments are additive. Scores are clamped to [0.0, 10.0].

### Why these approximations differ from official scores

The official CVSS v4.0 algorithm uses `EQ` (Equivalence) levels — groups of metric combinations that share a score level. The interaction between groups (especially between the Exploitability, Complexity, Vulnerable Impact, and Subsequent Impact groups) produces non-linear score changes. A single metric change can have different effects depending on the values of all other metrics simultaneously.

The heuristic treats adjustments as independent, additive deltas — this is an approximation that works reasonably well for mid-range scores but can diverge meaningfully at extremes.

---

## Step 4: Environmental Metrics from Asset Profile

Profiles encode typical network and data context for common asset categories. They apply CVSS Environmental metrics that reflect:

- Network zone (MAV: — how exposed the system is)
- Access controls (MAC: — how hard exploitation is)
- Subsequent system impact (MSC/MSI/MSA: — blast radius)
- Security requirements (CR/IR/AR: — how much CIA matters here)

Profile values are defaults. They may not reflect your specific infrastructure. Always verify environmental claims against actual firewall rules, network diagrams, and access control policies before using the output for compliance or audit purposes.

---

## Authoritative Scoring

For any finding that will drive a compliance decision, ticket escalation, or executive report, verify the heuristic estimate using the official FIRST.org CVSS v4.0 calculator:

1. Take the `enriched_vector` field from the CSV/JSON output
2. Paste it into the [FIRST.org CVSS v4.0 calculator](https://www.first.org/cvss/calculator/4-0)
3. The calculator's output is the authoritative CVSS-BTE score

The enriched vector string produced by this tool is a valid starting point for that calculation — the heuristic is in the numeric delta, not in the vector structure.

---

## References

- CVSS v4.0 Specification: https://www.first.org/cvss/v4-0/
- CVSS v4.0 User Guide: https://www.first.org/cvss/user-guide
- CVSS v4.0 Consumer Implementation Guide: https://www.first.org/cvss/v4.0/implementation-guide
- EPSS (Exploit Prediction Scoring System): https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
