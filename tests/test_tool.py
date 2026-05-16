"""
Basic unit tests for cvss_enrichment_tool.py

These tests cover the core scoring logic without making network requests.
They verify that:
  - CISA KEV entry → E:A (confirmed exploitation)
  - EPSS ≥ 0.1 → E:U + epss_verify=True (triage flag, NOT automatic E:P)
  - EPSS < 0.1 → E:U + epss_verify=False
  - heuristic_priority score adjustments are directionally correct
  - enriched vector is built correctly from profile

Run: python3 -m pytest tests/test_tool.py -v
Or:  python3 tests/test_tool.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cvss_enrichment_tool import (
    determine_exploit_maturity,
    heuristic_priority,
    build_enriched_vector,
    nvd_severity,
    BUILT_IN_PROFILES,
)


# ── determine_exploit_maturity ────────────────────────────────────────────────

def test_kev_sets_ea():
    """CISA KEV entry → E:A, no EPSS verify flag."""
    kev = {"CVE-2021-44228": {"cveID": "CVE-2021-44228", "dueDate": "2021-12-24",
                               "vulnerabilityName": "Log4Shell"}}
    epss = {"CVE-2021-44228": 0.9446}
    e_val, rationale, verify = determine_exploit_maturity("CVE-2021-44228", kev, epss)
    assert e_val == "E:A", f"Expected E:A for KEV entry, got {e_val}"
    assert verify is False, "KEV entry should not set epss_verify=True"
    assert "KEV" in rationale


def test_high_epss_not_in_kev_returns_eu_with_verify():
    """EPSS ≥ 0.5, not in KEV → E:U (NOT E:P) + epss_verify=True."""
    kev = {}
    epss = {"CVE-2025-99999": 0.75}
    e_val, rationale, verify = determine_exploit_maturity("CVE-2025-99999", kev, epss)
    assert e_val == "E:U", f"EPSS alone must not set E:P or E:A, got {e_val}"
    assert verify is True, "High EPSS should set epss_verify=True"


def test_moderate_epss_not_in_kev_returns_eu_with_verify():
    """EPSS 0.1–0.5, not in KEV → E:U + epss_verify=True."""
    kev = {}
    epss = {"CVE-2025-99998": 0.15}
    e_val, rationale, verify = determine_exploit_maturity("CVE-2025-99998", kev, epss)
    assert e_val == "E:U", f"EPSS alone must not set E:P, got {e_val}"
    assert verify is True


def test_low_epss_returns_eu_no_verify():
    """EPSS < 0.1, not in KEV → E:U, no verify flag."""
    kev = {}
    epss = {"CVE-2025-99997": 0.03}
    e_val, rationale, verify = determine_exploit_maturity("CVE-2025-99997", kev, epss)
    assert e_val == "E:U"
    assert verify is False


def test_missing_epss_defaults_to_eu():
    """CVE not in EPSS response → E:U, no verify flag."""
    kev = {}
    epss = {}
    e_val, rationale, verify = determine_exploit_maturity("CVE-2025-00000", kev, epss)
    assert e_val == "E:U"
    assert verify is False


# ── heuristic_priority ────────────────────────────────────────────────────────

def test_ea_keeps_high_base_critical():
    """E:A on a 10.0 base should stay Critical."""
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A"
    band, sla = heuristic_priority(vector, 10.0)
    assert band == "Critical", f"E:A + 10.0 base should be Critical, got {band}"


def test_eu_reduces_score():
    """E:U should reduce a 9.8 Critical to a lower band."""
    vector_eu = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U"
    band, _ = heuristic_priority(vector_eu, 9.8)
    assert band in ("High", "Medium"), f"E:U should reduce 9.8, got {band}"


def test_mav_a_reduces_score():
    """MAV:A should reduce priority compared to AV:N baseline."""
    vector_n  = "CVSS:4.0/AV:N/AC:L/.../E:A"
    vector_a  = "CVSS:4.0/AV:N/AC:L/.../E:A/MAV:A"
    base = 9.0
    band_n, _ = heuristic_priority(vector_n, base)
    band_a, _ = heuristic_priority(vector_a, base)
    scores_n = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}
    assert scores_n.get(band_a, 0) <= scores_n.get(band_n, 0), \
        f"MAV:A should not increase priority: {band_n} → {band_a}"


def test_mac_h_reduces_score():
    """MAC:H should reduce priority."""
    vector_base  = "CVSS:4.0/.../E:A"
    vector_mach  = "CVSS:4.0/.../E:A/MAC:H"
    base = 8.0
    band_base, _ = heuristic_priority(vector_base, base)
    band_mach, _ = heuristic_priority(vector_mach, base)
    scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}
    assert scores.get(band_mach, 0) <= scores.get(band_base, 0)


# ── build_enriched_vector ─────────────────────────────────────────────────────

def test_enriched_vector_appends_e_value():
    """E: value should be appended to the base vector."""
    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    profile = BUILT_IN_PROFILES["internal_vlan"]
    vec = build_enriched_vector(base, "E:A", profile, v4_base=True)
    assert "E:A" in vec


def test_enriched_vector_appends_mav():
    """internal_vlan profile should include MAV:A in the enriched vector."""
    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    profile = BUILT_IN_PROFILES["internal_vlan"]
    vec = build_enriched_vector(base, "E:U", profile, v4_base=True)
    assert "MAV:A" in vec, f"internal_vlan should set MAV:A, got: {vec}"


def test_internet_facing_no_mav():
    """internet_facing profile should not add MAV: (AV:N is correct)."""
    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    profile = BUILT_IN_PROFILES["internet_facing"]
    vec = build_enriched_vector(base, "E:A", profile, v4_base=True)
    assert "MAV:" not in vec, f"internet_facing should not add MAV:, got: {vec}"


# ── nvd_severity ──────────────────────────────────────────────────────────────

def test_nvd_severity_bands():
    assert nvd_severity(10.0) == "Critical"
    assert nvd_severity(9.0)  == "Critical"
    assert nvd_severity(8.9)  == "High"
    assert nvd_severity(7.0)  == "High"
    assert nvd_severity(6.9)  == "Medium"
    assert nvd_severity(4.0)  == "Medium"
    assert nvd_severity(3.9)  == "Low"
    assert nvd_severity(0.1)  == "Low"
    assert nvd_severity(0.0)  == "None"
    assert nvd_severity(None) == "Unknown"


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_kev_sets_ea,
        test_high_epss_not_in_kev_returns_eu_with_verify,
        test_moderate_epss_not_in_kev_returns_eu_with_verify,
        test_low_epss_returns_eu_no_verify,
        test_missing_epss_defaults_to_eu,
        test_ea_keeps_high_base_critical,
        test_eu_reduces_score,
        test_mav_a_reduces_score,
        test_mac_h_reduces_score,
        test_enriched_vector_appends_e_value,
        test_enriched_vector_appends_mav,
        test_internet_facing_no_mav,
        test_nvd_severity_bands,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(failed)
