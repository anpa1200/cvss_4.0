#!/usr/bin/env python3
"""
CVSS v4.0 Enrichment Assistant — Heuristic Prioritization Prototype

PURPOSE
  Takes CVE IDs and produces enriched prioritization data by pulling live
  data from CISA KEV, EPSS, and NVD. Outputs a ranked report with heuristic
  priority estimates and actionable SLA recommendations.

IMPORTANT LIMITATIONS
  - This tool produces HEURISTIC APPROXIMATIONS, not authoritative CVSS-BTE scores.
  - Score adjustments use empirical point-delta estimates (E:U −3.0, MAV:A −2.0,
    MAC:H −1.0), not the official CVSS v4.0 lookup tables.
  - NVD typically provides CVSS v3.1 vectors for CVEs scored before Nov 2023.
    Environmental metric adjustments applied to v3.1 base vectors are especially
    approximate. Re-score using the FIRST.org v4.0 calculator for authoritative results.
  - EPSS is used as a TRIAGE SIGNAL only. It does not prove PoC availability and
    does not directly set E:P or E:A. High EPSS flags CVEs for manual verification.
  - For authoritative CVSS-BTE scoring: https://www.first.org/cvss/calculator/4-0
  - This is not official FIRST.org tooling.

Usage:
  python3 cvss_enrichment_tool.py --cves CVE-2021-44228 CVE-2023-4966 CVE-2025-32433
  python3 cvss_enrichment_tool.py --file cves.txt --profile internal_vlan --output report.csv
  python3 cvss_enrichment_tool.py --cves CVE-2024-21762 --profile internet_facing

Requires: pip3 install requests
Python:   3.8+
"""

import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Tuple, List

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not installed. Run: pip3 install requests", file=sys.stderr)
    sys.exit(1)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class AssetProfile:
    """Environmental metric profile for an asset group."""
    name: str
    mav: str = "X"   # Modified Attack Vector
    mac: str = "X"   # Modified Attack Complexity
    mat: str = "X"   # Modified Attack Requirements
    mpr: str = "X"   # Modified Privileges Required
    mui: str = "X"   # Modified User Interaction
    mvc: str = "X"   # Modified Vulnerable System Confidentiality
    mvi: str = "X"   # Modified Vulnerable System Integrity
    mva: str = "X"   # Modified Vulnerable System Availability
    msc: str = "X"   # Modified Subsequent System Confidentiality
    msi: str = "X"   # Modified Subsequent System Integrity
    msa: str = "X"   # Modified Subsequent System Availability
    cr:  str = "X"   # Confidentiality Requirement
    ir:  str = "X"   # Integrity Requirement
    ar:  str = "X"   # Availability Requirement


@dataclass
class EnrichmentResult:
    cve: str
    cvss_version: str
    base_vector: str
    base_score: Optional[float]
    base_severity: str            # Severity from NVD base score (before any enrichment)
    in_kev: bool
    kev_due_date: str
    epss: float
    epss_verify: bool             # True if EPSS ≥ 0.1 → manual PoC verification recommended
    exploit_maturity: str         # E:A / E:P / E:U
    exploit_rationale: str
    asset_profile: str
    enriched_vector: str          # Base + Threat (+ Environmental if v4.0 base)
    heuristic_priority: str       # Approximate severity after enrichment (Critical/High/Medium/Low)
    recommended_sla: str
    notes: str                    # Warnings, flags, manual action items


# ── Built-in asset profiles ───────────────────────────────────────────────────

BUILT_IN_PROFILES: dict = {
    "internet_facing": AssetProfile(
        name="Internet-Facing Services",
        cr="H", ir="H", ar="H",
    ),
    "internal_vlan": AssetProfile(
        name="Internal VLAN Systems",
        mav="A",
        mac="H",
        cr="M", ir="M", ar="M",
    ),
    "isolated_ot": AssetProfile(
        name="OT/ICS Isolated Network",
        mav="A",
        mac="H",
        cr="L", ir="H", ar="H",
        msc="N", msi="N", msa="N",
    ),
    "dev_test": AssetProfile(
        name="Development / Test Environment",
        mav="L",
        cr="L", ir="L", ar="L",
    ),
    "healthcare_ehr": AssetProfile(
        name="Healthcare EHR / PHI System",
        cr="H", ir="H", ar="H",
    ),
    "pci_payment": AssetProfile(
        name="PCI-DSS Payment Processing",
        cr="H", ir="H", ar="H",
    ),
}


# ── API helpers ───────────────────────────────────────────────────────────────

def load_kev_catalog(verbose: bool = False) -> dict:
    """Download CISA KEV catalog. Returns dict CVE-ID → entry metadata."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    if verbose:
        print(f"  Fetching CISA KEV catalog from {url} ...", flush=True)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    catalog = {v["cveID"]: v for v in resp.json()["vulnerabilities"]}
    if verbose:
        print(f"  Loaded {len(catalog):,} KEV entries", flush=True)
    return catalog


def get_epss_scores(cve_ids: List[str], verbose: bool = False) -> dict:
    """
    Fetch EPSS scores from FIRST.org API.
    Returns dict CVE-ID → float probability (0.0–1.0).

    Note: EPSS estimates the probability of exploitation in the next 30 days.
    It is used here as a triage signal to flag CVEs for manual verification,
    not as direct evidence for setting E:P or E:A.
    """
    scores = {}
    url = "https://api.first.org/data/v1/epss"
    if verbose:
        print(f"  Fetching EPSS scores for {len(cve_ids)} CVEs ...", flush=True)

    for i in range(0, len(cve_ids), 30):
        batch = ",".join(cve_ids[i:i+30])
        try:
            resp = requests.get(f"{url}?cve={batch}", timeout=15)
            if resp.ok:
                for item in resp.json().get("data", []):
                    scores[item["cve"]] = float(item["epss"])
        except requests.RequestException as exc:
            print(f"  EPSS API error (batch {i}): {exc}", file=sys.stderr)
        time.sleep(0.5)

    return scores


def get_nvd_vector(cve_id: str, api_key: str = "") -> Tuple[Optional[str], str, Optional[float]]:
    """
    Fetch CVSS vector from NVD API 2.0.
    Returns (vector_string, cvss_version, base_score).
    Returns (None, "", None) if not found.

    Note: NVD only publishes CVSS v4.0 vectors for CVEs with NVD v4.0 assessment.
    Many CVEs — including recently published ones — only have CVSS v3.1 in NVD.
    The CVSS version column in output indicates which version NVD returned.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        for vuln in data.get("vulnerabilities", []):
            metrics = vuln["cve"].get("metrics", {})
            if "cvssMetricV40" in metrics:
                entry = metrics["cvssMetricV40"][0]
                return (
                    entry["cvssData"]["vectorString"],
                    "4.0",
                    entry["cvssData"].get("baseScore"),
                )
            if "cvssMetricV31" in metrics:
                entry = metrics["cvssMetricV31"][0]
                return (
                    entry["cvssData"]["vectorString"],
                    "3.1",
                    entry["cvssData"].get("baseScore"),
                )
    except requests.RequestException as exc:
        print(f"  NVD API error for {cve_id}: {exc}", file=sys.stderr)
    except (KeyError, IndexError) as exc:
        print(f"  NVD response parse error for {cve_id}: {exc}", file=sys.stderr)

    return None, "", None


# ── Scoring logic ─────────────────────────────────────────────────────────────

def determine_exploit_maturity(
    cve_id: str, kev: dict, epss_scores: dict
) -> Tuple[str, str, bool]:
    """
    Determine Exploit Maturity (E) metric, rationale string, and verify flag.

    Returns (e_value, rationale, epss_verify)
      e_value:     "E:A" | "E:P" | "E:U"
      rationale:   human-readable source explanation
      epss_verify: True if EPSS ≥ 0.1 → analyst should manually check for PoC

    CVSS v4.0 specification defines:
      E:A  Attacks in the wild / exploit tooling confirmed
      E:P  Public proof-of-concept exists, no confirmed attacks
      E:U  No PoC, no reported attacks, no exploit tooling found

    This function sets E: based on CONFIRMED evidence only:
      CISA KEV entry → E:A (confirmed active exploitation)
      Otherwise      → E:U (default — conservative)

    EPSS is a triage signal for manual verification, NOT a source for E:.
    EPSS ≥ 0.1 sets epss_verify=True to flag for ExploitDB/Metasploit check.
    If that check finds a public PoC → manually set E:P in your tracking system.
    If that check finds active exploitation evidence → manually set E:A.
    """
    if cve_id in kev:
        entry = kev[cve_id]
        due = entry.get("dueDate", "N/A")
        name = entry.get("vulnerabilityName", "")
        return "E:A", f"CISA KEV — confirmed exploitation — due {due} — {name}", False

    score = epss_scores.get(cve_id, 0.0)
    if score >= 0.5:
        rationale = (
            f"EPSS={score:.4f} (≥0.5 — HIGH probability). "
            "Not in KEV. E:U pending manual verification. "
            "Check ExploitDB/Metasploit/GitHub/vendor advisory."
        )
        return "E:U", rationale, True   # epss_verify=True → review needed
    elif score >= 0.1:
        rationale = (
            f"EPSS={score:.4f} (≥0.1 — moderate probability). "
            "Not in KEV. E:U pending manual verification. "
            "Check ExploitDB/Metasploit."
        )
        return "E:U", rationale, True   # epss_verify=True → review needed
    else:
        return "E:U", f"EPSS={score:.4f} (<0.1) — not in KEV — no current exploitation evidence", False


def build_enriched_vector(base_vector: str, e_value: str, profile: AssetProfile,
                          v4_base: bool) -> str:
    """
    Append Threat and Environmental metrics to a vector string.
    Only non-X (non-default) values are appended.

    If v4_base is False (v3.1 source vector), Environmental metrics are still
    appended for heuristic calculation but the result is NOT a valid CVSS v4.0
    vector — it is used only for heuristic priority estimation.
    """
    parts = [e_value]
    for attr in ["mav","mac","mat","mpr","mui","mvc","mvi","mva","msc","msi","msa","cr","ir","ar"]:
        val = getattr(profile, attr)
        if val != "X":
            parts.append(f"{attr.upper()}:{val}")
    return f"{base_vector}/{'/'.join(parts)}"


def nvd_severity(score: Optional[float]) -> str:
    """Convert NVD base score to severity label."""
    if score is None:
        return "Unknown"
    if score >= 9.0:  return "Critical"
    if score >= 7.0:  return "High"
    if score >= 4.0:  return "Medium"
    if score > 0.0:   return "Low"
    return "None"


def heuristic_priority(enriched_vector: str, base_score: Optional[float]) -> Tuple[str, str]:
    """
    Approximate operational priority and SLA from base score + enrichment heuristics.

    WARNING: These are EMPIRICAL APPROXIMATIONS.
    Actual CVSS v4.0 scoring uses lookup tables, not formulas.
    Use the FIRST.org calculator for authoritative scores:
      https://www.first.org/cvss/calculator/4-0

    Empirical adjustments (approximate ranges from FIRST.org calculator observations):
      E:U  → −2.5 to −3.5 pts (using −3.0)
      E:P  → −1.0 to −1.5 pts (using −1.2)
      MAV:A → −1.5 to −2.5 pts (using −2.0)
      MAV:L → −2.5 to −3.5 pts (using −3.0)
      MAC:H → −0.5 to −1.5 pts (using −1.0)
      MSC:N/MSI:N/MSA:N → −0.5 to −1.5 pts (using −0.8 combined)
      CR:L/IR:L/AR:L → −0.3 to −0.8 pts per metric (using −0.3)
      CR:H/IR:H/AR:H → +0.3 to +0.8 pts per metric (using +0.3)
    """
    score = base_score or 0.0

    if "/E:U/" in enriched_vector or enriched_vector.endswith("/E:U"):
        score = max(0.0, score - 3.0)
    elif "/E:P/" in enriched_vector or enriched_vector.endswith("/E:P"):
        score = max(0.0, score - 1.2)

    if "/MAV:A/" in enriched_vector or enriched_vector.endswith("/MAV:A"):
        score = max(0.0, score - 2.0)
    elif "/MAV:L/" in enriched_vector or enriched_vector.endswith("/MAV:L"):
        score = max(0.0, score - 3.0)
    elif "/MAV:P/" in enriched_vector or enriched_vector.endswith("/MAV:P"):
        score = max(0.0, score - 4.0)

    if "/MAC:H/" in enriched_vector or enriched_vector.endswith("/MAC:H"):
        score = max(0.0, score - 1.0)

    # Subsequent system impact reduction
    if "/MSC:N/" in enriched_vector or enriched_vector.endswith("/MSC:N"):
        score = max(0.0, score - 0.4)
    if "/MSI:N/" in enriched_vector or enriched_vector.endswith("/MSI:N"):
        score = max(0.0, score - 0.2)
    if "/MSA:N/" in enriched_vector or enriched_vector.endswith("/MSA:N"):
        score = max(0.0, score - 0.2)

    # Security requirements
    for metric in ["CR", "IR", "AR"]:
        if f"/{metric}:H/" in enriched_vector or enriched_vector.endswith(f"/{metric}:H"):
            score = min(10.0, score + 0.3)
        elif f"/{metric}:L/" in enriched_vector or enriched_vector.endswith(f"/{metric}:L"):
            score = max(0.0, score - 0.3)

    score = round(score, 1)

    if score >= 9.0:   return "Critical", "24–72 hours"
    elif score >= 7.0: return "High",     "30 days"
    elif score >= 4.0: return "Medium",   "90 days"
    elif score > 0.0:  return "Low",      "Next release"
    else:              return "None",     "Informational"


# ── Main pipeline ─────────────────────────────────────────────────────────────

def enrich_cves(
    cve_ids: List[str],
    profile: AssetProfile,
    nvd_api_key: str = "",
    verbose: bool = False,
) -> List[EnrichmentResult]:
    """
    Full enrichment pipeline.
    Returns list of EnrichmentResult, one per CVE.
    """
    kev = load_kev_catalog(verbose)
    epss = get_epss_scores(cve_ids, verbose)

    results = []
    for cve_id in cve_ids:
        if verbose:
            print(f"  Processing {cve_id} ...", flush=True)

        base_vector, cvss_ver, base_score = get_nvd_vector(cve_id, nvd_api_key)
        time.sleep(0.7)  # NVD free-tier: 5 req/30 s

        kev_entry = kev.get(cve_id, {})
        e_value, e_rationale, epss_verify = determine_exploit_maturity(cve_id, kev, epss)

        notes_parts = []

        if not base_vector:
            enriched_vector = "N/A — vector not found in NVD"
            priority_band, sla = "UNKNOWN", "Check manually"
            base_sev = "Unknown"
            notes_parts.append(
                "No CVSS vector in NVD. Score manually via FIRST.org calculator."
            )
        else:
            base_sev = nvd_severity(base_score)
            v4_base = (cvss_ver == "4.0")

            # Build enriched vector (always include environmental metrics for heuristic)
            enriched_vector = build_enriched_vector(base_vector, e_value, profile, v4_base)
            priority_band, sla = heuristic_priority(enriched_vector, base_score)

            if not v4_base:
                notes_parts.append(
                    f"NVD has CVSS {cvss_ver} vector only. "
                    "Environmental adjustment applied as heuristic. "
                    "Re-score at https://www.first.org/cvss/calculator/4-0"
                )

        if epss_verify:
            notes_parts.append(
                f"VERIFY: EPSS={epss.get(cve_id, 0.0):.3f} — "
                "check ExploitDB/Metasploit/GitHub; upgrade E: if PoC/exploit confirmed"
            )

        results.append(EnrichmentResult(
            cve=cve_id,
            cvss_version=cvss_ver or "NOT_FOUND",
            base_vector=base_vector or "",
            base_score=base_score,
            base_severity=base_sev,
            in_kev=bool(kev_entry),
            kev_due_date=kev_entry.get("dueDate", ""),
            epss=epss.get(cve_id, 0.0),
            epss_verify=epss_verify,
            exploit_maturity=e_value,
            exploit_rationale=e_rationale,
            asset_profile=profile.name,
            enriched_vector=enriched_vector,
            heuristic_priority=priority_band,
            recommended_sla=sla,
            notes=" | ".join(notes_parts),
        ))

    return results


# ── Output helpers ────────────────────────────────────────────────────────────

def print_table(results: List[EnrichmentResult]) -> None:
    """
    Print a formatted summary table to stdout.

    Columns:
      CVE         — CVE identifier
      CVSS        — CVSS version from NVD (3.1 or 4.0)
      KEV         — In CISA KEV? (YES = confirmed active exploitation)
      EPSS        — EPSS probability (0–1); ⚠ = verify PoC manually
      E:          — Exploit Maturity assigned (A/P/U)
      NVD Sev     — Original NVD Base severity (before enrichment)
      Priority    — Heuristic priority after E: and profile adjustment
      SLA         — Recommended remediation timeline
      Flags       — Action items (VERIFY PoC, v3.1 re-score, etc.)
    """
    sep = "─" * 120
    header = (
        f"{'CVE':<22} {'CVSS':>5}  {'KEV':>4}  {'EPSS':>7}  {'E:':<5}  "
        f"{'NVD Sev':<10}  {'→ Priority':<12}  {'SLA':<16}  Flags"
    )
    print()
    print(sep)
    print(header)
    print(sep)
    for r in results:
        kev_flag = "YES" if r.in_kev else " no"
        epss_str = f"{r.epss:.4f}" if r.epss else "  N/A"
        epss_warn = "⚠" if r.epss_verify else " "
        priority_arrow = f"→ {r.heuristic_priority}"
        flags = []
        if r.epss_verify:
            flags.append("VERIFY PoC")
        if "v3.1" in r.notes or "3.1 vector" in r.notes:
            flags.append("v3.1→re-score")
        flags_str = " | ".join(flags)

        print(
            f"{r.cve:<22} {r.cvss_version:>5}  {kev_flag:>4}  {epss_warn}{epss_str}  "
            f"{r.exploit_maturity:<5}  {r.base_severity:<10}  {priority_arrow:<12}  "
            f"{r.recommended_sla:<16}  {flags_str}"
        )
    print(sep)
    print()
    print("  NVD Sev    = Severity from NVD base score (before any enrichment)")
    print("  → Priority = Heuristic estimate after E: and profile adjustments")
    print("  ⚠          = EPSS ≥ 0.1: manually verify PoC before treating as E:U final")
    print("  VERIFY PoC = Check ExploitDB/Metasploit/GitHub; upgrade E: if PoC found")
    print("  v3.1→re-score = NVD has v3.1 only; env. adjustment is approximate")
    print()
    print("  ⚠ Priority column is HEURISTIC — not authoritative CVSS-BTE scoring.")
    print("  Verify important findings at: https://www.first.org/cvss/calculator/4-0")
    print()


def write_csv(results: List[EnrichmentResult], output_path: str) -> None:
    """Write results to CSV file."""
    if not results:
        return
    fieldnames = list(EnrichmentResult.__dataclass_fields__.keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({k: getattr(r, k) for k in fieldnames})
    print(f"CSV saved: {output_path}")


def write_json(results: List[EnrichmentResult], output_path: str) -> None:
    """Write results to JSON file."""
    data = [{k: getattr(r, k) for k in EnrichmentResult.__dataclass_fields__} for r in results]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"JSON saved: {output_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "CVSS v4.0 Enrichment Assistant — Heuristic Prioritization Prototype\n"
            "Fetches CVE data from NVD, CISA KEV, and EPSS; applies asset profiles;\n"
            "outputs heuristic priority estimates. Not a CVSS-BTE calculator.\n"
            "For authoritative scores: https://www.first.org/cvss/calculator/4-0"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --cves CVE-2021-44228 CVE-2023-4966
  %(prog)s --file my_cves.txt --profile internal_vlan --output report.csv
  %(prog)s --cves CVE-2024-21762 --profile internet_facing --apikey YOUR_KEY
  %(prog)s --list-profiles

Built-in profiles:
  internet_facing    CR:H/IR:H/AR:H (no network modification)
  internal_vlan      MAV:A/MAC:H/CR:M/IR:M/AR:M
  isolated_ot        MAV:A/MAC:H/CR:L/IR:H/AR:H/MSC:N/MSI:N/MSA:N
  dev_test           MAV:L/CR:L/IR:L/AR:L
  healthcare_ehr     CR:H/IR:H/AR:H
  pci_payment        CR:H/IR:H/AR:H
        """
    )
    parser.add_argument("--cves", nargs="+", metavar="CVE-ID",
                        help="One or more CVE IDs to enrich")
    parser.add_argument("--file", metavar="PATH",
                        help="Text file with one CVE ID per line")
    parser.add_argument("--profile", default="internal_vlan",
                        choices=list(BUILT_IN_PROFILES.keys()),
                        help="Asset profile for environmental metrics (default: internal_vlan)")
    parser.add_argument("--output", metavar="PATH",
                        help="Output CSV file path")
    parser.add_argument("--json", metavar="PATH",
                        help="Also write JSON output to this path")
    parser.add_argument("--apikey", default="", metavar="KEY",
                        help="NVD API key (free at nvd.nist.gov/developers/request-an-api-key)")
    parser.add_argument("--list-profiles", action="store_true",
                        help="List all built-in profiles and exit")
    parser.add_argument("--verbose", action="store_true",
                        help="Print progress to stdout")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_profiles:
        print("\nBuilt-in Asset Profiles:")
        print("-" * 60)
        for key, p in BUILT_IN_PROFILES.items():
            mods = {
                k: getattr(p, k) for k in AssetProfile.__dataclass_fields__
                if k != "name" and getattr(p, k) != "X"
            }
            mods_str = "  ".join(f"{k.upper()}:{v}" for k, v in mods.items()) or "(base defaults only)"
            print(f"  {key:<20} {p.name}")
            print(f"    Metrics: {mods_str}")
        print()
        sys.exit(0)

    # Collect CVE IDs
    cve_ids: List[str] = []
    if args.cves:
        cve_ids.extend(args.cves)
    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        cve_ids.append(stripped)
        except FileNotFoundError:
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not cve_ids:
        print("ERROR: No CVE IDs provided. Use --cves or --file.", file=sys.stderr)
        sys.exit(1)

    # Deduplicate preserving order
    seen: set = set()
    cve_ids = [c for c in cve_ids if not (c in seen or seen.add(c))]

    profile = BUILT_IN_PROFILES[args.profile]
    print()
    print("CVSS v4.0 Enrichment Assistant — Heuristic Prioritization Prototype")
    print("  ⚠ Priority estimates are approximate — not authoritative CVSS-BTE scores")
    print(f"  CVEs:    {len(cve_ids)}")
    print(f"  Profile: {profile.name}")
    print(f"  NVD key: {'provided' if args.apikey else 'none (5 req/30s limit)'}")
    print()

    results = enrich_cves(cve_ids, profile, args.apikey, args.verbose)

    print_table(results)

    if args.output:
        write_csv(results, args.output)
    if args.json:
        write_json(results, args.json)

    # Exit summary
    critical  = sum(1 for r in results if r.heuristic_priority == "Critical")
    high      = sum(1 for r in results if r.heuristic_priority == "High")
    medium    = sum(1 for r in results if r.heuristic_priority == "Medium")
    low       = sum(1 for r in results if r.heuristic_priority in ("Low", "None"))
    to_verify = sum(1 for r in results if r.epss_verify)

    print(f"Heuristic summary: {critical} Critical  {high} High  {medium} Medium  {low} Low")
    if to_verify:
        print(f"Manual verification needed: {to_verify} CVE(s) with EPSS ≥ 0.1 — check ExploitDB/Metasploit")
    print()


if __name__ == "__main__":
    main()
