"""Live NVD CVE smoke test for CyberOrchestra.

This script performs a LIVE connection to the NVD CVE API 2.0.

Usage:
    python scripts/smoke_test_nvd.py CVE-2021-44228
    python scripts/smoke_test_nvd.py CVE-2024-12345

IMPORTANT:
- This is a live test against the real NVD API. Do NOT add it to the automated pytest suite.
- Supply a REAL, publicly documented CVE ID at runtime.
- Do NOT use synthetic CyberOrchestra CVE IDs (e.g., CVE-2026-10001) — they don't exist in NVD.
- The NVD API key is optional but recommended. Configure NVD_API_KEY in backend/.env.
- API keys are NEVER printed, logged, or exposed.
"""

import json
import sys
import os

# Support running from backend/ directory or from scripts/ sub-directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Ensure UTF-8 output on all platforms
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app.core.config import settings
from app.services.nvd_client import (
    NVDClient,
    NVDConnectionError,
    NVDInvalidCVEError,
    NVDNotFoundError,
    NVDRateLimitError,
    NVDResponseError,
)


def _mask(key: str | None) -> str:
    """Return a safe masked representation of a key for display."""
    if not key or not key.strip():
        return "[NOT CONFIGURED — unauthenticated request, lower rate limit]"
    stripped = key.strip()
    visible = stripped[:4]
    return f"{visible}{'*' * min(8, len(stripped) - 4)} [CONFIGURED / PROTECTED]"


def run_smoke_test(cve_id: str) -> None:
    print("=" * 70)
    print("CyberOrchestra NVD CVE Live Smoke Test")
    print("=" * 70)

    api_key_display = _mask(settings.NVD_API_KEY)
    print(f"\n[*] NVD API Key:     {api_key_display}")
    print(f"[*] NVD Endpoint:    {settings.NVD_API_URL}")
    print(f"[*] Target CVE ID:   {cve_id}")
    print(f"\n[*] Sending request to NVD CVE API 2.0...")

    nvd = NVDClient()

    try:
        result = nvd.get_cve_and_convert(cve_id=cve_id)
    except NVDInvalidCVEError as e:
        print(f"\n[!] INVALID CVE FORMAT: {e}")
        sys.exit(1)
    except NVDNotFoundError as e:
        print(f"\n[!] CVE NOT FOUND IN NVD: {e}")
        print("    Note: Use a real publicly documented CVE, not a synthetic one.")
        sys.exit(1)
    except NVDRateLimitError as e:
        print(f"\n[!] RATE LIMITED: {e}")
        print("    Tip: Set NVD_API_KEY in backend/.env for higher rate limits.")
        sys.exit(1)
    except NVDConnectionError as e:
        print(f"\n[!] CONNECTION FAILED: {e}")
        sys.exit(1)
    except NVDResponseError as e:
        print(f"\n[!] RESPONSE ERROR: {e}")
        sys.exit(1)

    print(f"\n[+] SUCCESS! Live NVD intelligence retrieved.")

    cve = result.cve_data
    print("\n--- NVD CVE Summary ---")
    print(f"  CVE ID:           {cve.cve_id}")
    print(f"  Status:           {cve.vuln_status or 'N/A'}")
    print(f"  Published:        {cve.published.date() if cve.published else 'N/A'}")
    print(f"  Last Modified:    {cve.last_modified.date() if cve.last_modified else 'N/A'}")
    print(f"  Source (CNA):     {cve.source_identifier or 'N/A'}")

    if cve.description:
        truncated = cve.description[:200] + ("..." if len(cve.description) > 200 else "")
        print(f"  Description:      {truncated}")

    if cve.cvss_v3:
        print(f"\n--- CVSS v3.x ---")
        print(f"  Version:          {cve.cvss_v3.cvss_version or 'N/A'}")
        print(f"  Base Score:       {cve.cvss_v3.base_score}")
        print(f"  Severity:         {cve.cvss_v3.base_severity}")
        print(f"  Vector:           {cve.cvss_v3.vector_string or 'N/A'}")
        print(f"  Attack Vector:    {cve.cvss_v3.attack_vector or 'N/A'}")
        print(f"  Attack Complexity:{cve.cvss_v3.attack_complexity or 'N/A'}")
        print(f"  NOTE: CVSS score is NOT mapped to CyberOrchestra confidence.")

    if cve.cvss_v2 and not cve.cvss_v3:
        print(f"\n--- CVSS v2 ---")
        print(f"  Base Score:       {cve.cvss_v2.base_score}")
        print(f"  Severity:         {cve.cvss_v2.base_severity}")

    if cve.cwes:
        print(f"\n--- CWE Weaknesses ---")
        for cwe in cve.cwes:
            print(f"  {cwe.cwe_id or cwe.description}")

    print(f"\n--- Affected Products ({len(cve.affected_products)} entries) ---")
    for p in cve.affected_products[:5]:
        print(f"  {p.vendor}/{p.product} — CPE: {(p.cpe_name or '')[:60]}")
    if len(cve.affected_products) > 5:
        print(f"  ... and {len(cve.affected_products) - 5} more")

    print(f"\n--- References ({len(cve.references)} total) ---")
    for ref in cve.references[:4]:
        print(f"  [{', '.join(ref.tags)}] {ref.url}")
    if len(cve.references) > 4:
        print(f"  ... and {len(cve.references) - 4} more")

    print(f"\n--- Standardized Indicator (CyberOrchestra) ---")
    ind_dict = result.indicator.model_dump()
    # Avoid printing metadata verbosely; just show top-level
    ind_display = {k: v for k, v in ind_dict.items() if k != "metadata"}
    print(json.dumps(ind_display, indent=2, default=str))
    print(f"  confidence: {result.indicator.confidence}  (NOT mapped from CVSS)")

    print(f"\n--- Standardized Evidence (CyberOrchestra) ---")
    ev_dict = result.evidence.model_dump()
    ev_display = {k: v for k, v in ev_dict.items() if k != "metadata"}
    print(json.dumps(ev_display, indent=2, default=str))
    print(f"  confidence: {result.evidence.confidence}  (NOT mapped from CVSS)")

    print(f"\n[*] NVD URL: {cve.nvd_url}")
    print("\n" + "=" * 70)
    print("Live Smoke Test Passed.")
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/smoke_test_nvd.py <CVE-ID>")
        print("Example: python scripts/smoke_test_nvd.py CVE-2021-44228")
        print("\nNote: Use a real, publicly documented CVE ID.")
        print("Do NOT use synthetic CyberOrchestra CVE IDs (e.g. CVE-2026-10001).")
        sys.exit(1)

    run_smoke_test(sys.argv[1])
