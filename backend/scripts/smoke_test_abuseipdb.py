"""Smoke test for AbuseIPDB integration.

Supports two modes:
1. Live Mode (default): Queries the official AbuseIPDB API v2 check endpoint.
   Requires ABUSEIPDB_API_KEY in the environment or in backend/.env.
2. Simulated/Demo Mode (--demo or --mock): Runs an end-to-end smoke test using
   a realistic AbuseIPDB response without requiring an active API key or internet access.

USAGE:
    python backend/scripts/smoke_test_abuseipdb.py [IP_ADDRESS]
    python backend/scripts/smoke_test_abuseipdb.py --demo [IP_ADDRESS]

EXAMPLES:
    python backend/scripts/smoke_test_abuseipdb.py --demo
    python backend/scripts/smoke_test_abuseipdb.py 1.1.1.1
"""

import ipaddress
import json
import os
import sys
from pathlib import Path
import httpx

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add backend directory to sys.path so app packages can be imported
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.services.abuseipdb_client import (
    AbuseIPDBClient,
    AbuseIPDBConfigError,
    AbuseIPDBError,
    abuseipdb_client,
)

RFC_5737_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def run_demo_smoke_test(ip_address: str = "118.25.6.39"):
    print("=" * 70)
    print("CyberOrchestra AbuseIPDB Smoke Test (Demo / Simulated Mode)")
    print("=" * 70)
    print(f"[*] Target IP:          {ip_address}")
    print("[*] Mode:               Mock Transport (Simulated AbuseIPDB API v2 check)")

    sample_api_response = {
        "data": {
            "ipAddress": ip_address,
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 92,
            "countryCode": "CN",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Tencent Cloud Computing",
            "domain": "tencent.com",
            "hostnames": [],
            "isTor": False,
            "totalReports": 28,
            "numDistinctUsers": 12,
            "lastReportedAt": "2026-09-30T08:15:00+00:00",
        }
    }

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=sample_api_response)

    client = AbuseIPDBClient(api_key="demo_simulated_key")
    result = client.check_and_convert(ip_address=ip_address, transport=httpx.MockTransport(mock_handler))

    print("\n[+] SUCCESS! Smoke test completed. Normalized evidence generated:\n")
    print("--- 1. Extracted AbuseIPDB Reputation ---")
    print(result.reputation.model_dump_json(indent=2))

    print("\n--- 2. Standardized CyberOrchestra Indicator ---")
    print(result.indicator.model_dump_json(indent=2))

    print("\n--- 3. Standardized CyberOrchestra Evidence ---")
    print(result.evidence.model_dump_json(indent=2))

    print("\n" + "=" * 70)
    print("Smoke Test Passed: Normalizer schema contracts fully satisfied.")
    print("=" * 70)


def run_live_smoke_test(ip_address: str):
    print("=" * 70)
    print("CyberOrchestra AbuseIPDB Live Smoke Test")
    print("=" * 70)

    # 1. Check API Key configuration
    api_key = settings.ABUSEIPDB_API_KEY or os.getenv("ABUSEIPDB_API_KEY")
    if not api_key or not api_key.strip():
        print("\n[!] ABUSEIPDB_API_KEY is not configured in environment or backend/.env.")
        print("    Running in --demo mode to verify pipeline correctness:\n")
        run_demo_smoke_test(ip_address if ip_address != "1.1.1.1" else "118.25.6.39")
        print("\n[INFO] To run with live API against https://api.abuseipdb.com:")
        print("  1. Add your key to backend/.env:  ABUSEIPDB_API_KEY=your_key_here")
        print(f"  2. Re-run: python backend/scripts/smoke_test_abuseipdb.py {ip_address}")
        return

    print("\n[*] API Key Status:    [CONFIGURED / PROTECTED]")
    print(f"[*] Target Endpoint:    {settings.ABUSEIPDB_API_URL}")
    print(f"[*] Target IP:          {ip_address}")

    # 2. Safety check: Warn if testing documentation IP
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if any(ip_obj in net for net in RFC_5737_NETWORKS):
            print("\n[!] WARNING: Target IP belongs to RFC 5737 documentation subnets.")
            print("    RFC 5737 addresses are documentation-safe test fixtures and have no real internet reputation.")
            print("    Please provide a public IP address (e.g. 1.1.1.1 or 8.8.8.8) to test live reputation lookup.")
    except ValueError as e:
        print(f"\n[ERROR] Invalid IP address syntax: {e}")
        sys.exit(1)

    # 3. Perform live query and conversion
    print("\n[*] Sending request to AbuseIPDB API v2 check endpoint...")
    try:
        result = abuseipdb_client.check_and_convert(ip_address=ip_address, max_age_in_days=30)
    except AbuseIPDBConfigError as e:
        print(f"\n[ERROR] Configuration error: {e}")
        sys.exit(1)
    except AbuseIPDBError as e:
        print(f"\n[ERROR] AbuseIPDB API communication failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)

    # 4. Display results
    print("\n[+] SUCCESS! Live reputation retrieved and converted into standardized schema:\n")
    print("--- Extracted AbuseIPDB Reputation ---")
    print(result.reputation.model_dump_json(indent=2))

    print("\n--- Standardized Indicator (CyberOrchestra) ---")
    print(result.indicator.model_dump_json(indent=2))

    print("\n--- Standardized Evidence (CyberOrchestra) ---")
    print(result.evidence.model_dump_json(indent=2))

    print("\n" + "=" * 70)
    print("Live Smoke Test Passed.")
    print("=" * 70)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    is_demo = any(a in ("--demo", "--mock") for a in sys.argv[1:])

    target_ip = args[0].strip() if args else "1.1.1.1"

    if is_demo:
        run_demo_smoke_test(target_ip if target_ip != "1.1.1.1" else "118.25.6.39")
    else:
        run_live_smoke_test(target_ip)
