#!/usr/bin/env python3
"""
CVSS v4.0 Enrichment Tool
Fetches Base vectors from NVD, Exploit Maturity from CISA KEV + EPSS,
applies Environmental profiles, and outputs a prioritized CSV report.

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
    in_kev: bool
    kev_due_date: str
    epss: float
    exploit_maturity: str
    exploit_rationale: str
    asset_profile: str
    bte_vector: str
    severity_band: str
    recommended_sla: str
    notes: str


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

    Note: NVD only publishes CVSS v4.0 vectors for CVEs scored after Nov 2023.
    For older CVEs, the v3.1 vector is returned. Environmental enrichment
    requires a v4.0 base vector — see the notes field in results.
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
) -> Tuple[str, str]:
    """
    Determine Exploit Maturity (E) metric and rationale string.
    Decision order: CISA KEV → EPSS → default E:U.
    """
    if cve_id in kev:
        entry = kev[cve_id]
        due = entry.get("dueDate", "N/A")
        name = entry.get("vulnerabilityName", "")
        return "E:A", f"CISA KEV — due {due} — {name}"

    score = epss_scores.get(cve_id, 0.0)
    if score >= 0.5:
        return "E:P", f"EPSS={score:.4f} (≥0.5 — high exploitation probability; verify KEV/advisories)"
    elif score >= 0.1:
        return "E:P", f"EPSS={score:.4f} (≥0.1 — moderate; verify ExploitDB/Metasploit/GitHub)"
    else:
        return "E:U", f"EPSS={score:.4f} (<0.1), not in KEV — no current exploitation evidence"


def build_bte_vector(base_vector: str, e_value: str, profile: AssetProfile) -> str:
    """
    Append Threat and Environmental metrics to a v4.0 Base vector.
    Only non-X (non-default) values are appended.
    """
    parts = [e_value]
    for attr in ["mav","mac","mat","mpr","mui","mvc","mvi","mva","msc","msi","msa","cr","ir","ar"]:
        val = getattr(profile, attr)
        if val != "X":
            parts.append(f"{attr.upper()}:{val}")
    return f"{base_vector}/{'/'.join(parts)}"


def severity_band(bte_vector: str, base_score: Optional[float]) -> Tuple[str, str]:
    """
    Approximate severity band and SLA from score.
    Uses base_score as proxy since we can't compute v4.0 score without the full lookup table.
    For v4.0 vectors, direct calculation via FIRST.org API is recommended.
    """
    # NVD base score is our best approximation without a local v4.0 calculator
    score = base_score or 0.0

    # Partial adjustment: E:U in vector typically reduces by 2.5–3.5 pts
    if "/E:U/" in bte_vector or bte_vector.endswith("/E:U"):
        score = max(0.0, score - 3.0)
    elif "/E:P/" in bte_vector or bte_vector.endswith("/E:P"):
        score = max(0.0, score - 1.2)

    # MAV:A typically reduces by 1.5–2.5 pts
    if "/MAV:A/" in bte_vector or bte_vector.endswith("/MAV:A"):
        score = max(0.0, score - 2.0)
    elif "/MAV:L/" in bte_vector or bte_vector.endswith("/MAV:L"):
        score = max(0.0, score - 3.0)

    # MAC:H typically reduces by 0.5–1.5 pts
    if "/MAC:H/" in bte_vector or bte_vector.endswith("/MAC:H"):
        score = max(0.0, score - 1.0)

    if score >= 9.0:
        return "Critical", "24–72 hours"
    elif score >= 7.0:
        return "High", "30 days"
    elif score >= 4.0:
        return "Medium", "90 days"
    elif score > 0.0:
        return "Low", "Next release cycle"
    else:
        return "None", "Informational"


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
        e_value, e_rationale = determine_exploit_maturity(cve_id, kev, epss)

        notes = ""
        if not base_vector:
            bte_vector = "N/A — vector not found in NVD"
            band, sla = "UNKNOWN", "Check manually"
            notes = "No CVSS vector in NVD. Score manually via FIRST.org calculator."
        elif cvss_ver != "4.0":
            # v3.1 vector: threat-only enrichment, no environmental metrics
            bte_vector = f"{base_vector}/{e_value}"
            band, sla = severity_band(bte_vector, base_score)
            notes = (
                f"NVD only has CVSS {cvss_ver} vector. "
                "Environmental metrics (MAV, MSC, CR, etc.) require a v4.0 base vector. "
                "Re-score manually at https://www.first.org/cvss/calculator/4-0 "
                "then rerun with the v4.0 vector."
            )
        else:
            bte_vector = build_bte_vector(base_vector, e_value, profile)
            band, sla = severity_band(bte_vector, base_score)

        results.append(EnrichmentResult(
            cve=cve_id,
            cvss_version=cvss_ver or "NOT_FOUND",
            base_vector=base_vector or "",
            base_score=base_score,
            in_kev=bool(kev_entry),
            kev_due_date=kev_entry.get("dueDate", ""),
            epss=epss.get(cve_id, 0.0),
            exploit_maturity=e_value,
            exploit_rationale=e_rationale,
            asset_profile=profile.name,
            bte_vector=bte_vector,
            severity_band=band,
            recommended_sla=sla,
            notes=notes,
        ))

    return results


# ── Output helpers ────────────────────────────────────────────────────────────

def print_table(results: List[EnrichmentResult]) -> None:
    """Print a formatted summary table to stdout."""
    sep = "-" * 110
    header = f"{'CVE':<20} {'CVSS':>5}  {'KEV':>4}  {'EPSS':>7}  {'E':<5}  {'Severity':<10}  {'SLA':<20}  Notes"
    print()
    print(sep)
    print(header)
    print(sep)
    for r in results:
        kev_flag = "YES" if r.in_kev else "no"
        epss_str = f"{r.epss:.4f}" if r.epss else "N/A"
        notes_short = r.notes[:40] + "…" if len(r.notes) > 40 else r.notes
        print(
            f"{r.cve:<20} {r.cvss_version:>5}  {kev_flag:>4}  {epss_str:>7}  "
            f"{r.exploit_maturity:<5}  {r.severity_band:<10}  {r.recommended_sla:<20}  {notes_short}"
        )
    print(sep)
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
        description="CVSS v4.0 Enrichment Tool — fetch, enrich, and prioritize CVEs",
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
                        help="Output CSV file path (default: print to stdout only)")
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
    print(f"\nCVSS v4.0 Enrichment Tool")
    print(f"  CVEs:    {len(cve_ids)}")
    print(f"  Profile: {profile.name}")
    print(f"  NVD key: {'provided' if args.apikey else 'none (5 req/30s limit)'}\n")

    results = enrich_cves(cve_ids, profile, args.apikey, args.verbose)

    print_table(results)

    if args.output:
        write_csv(results, args.output)
    if args.json:
        write_json(results, args.json)

    # Exit summary
    critical = sum(1 for r in results if r.severity_band == "Critical")
    high     = sum(1 for r in results if r.severity_band == "High")
    medium   = sum(1 for r in results if r.severity_band == "Medium")
    low      = sum(1 for r in results if r.severity_band in ("Low", "None"))
    warned   = sum(1 for r in results if r.notes)

    print(f"Summary: {critical} Critical  {high} High  {medium} Medium  {low} Low")
    if warned:
        print(f"Warnings: {warned} CVE(s) have notes — check the Notes column")
    print()


if __name__ == "__main__":
    main()
