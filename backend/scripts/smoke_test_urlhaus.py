"""Smoke test for URLhaus threat intelligence integration.

Supports two modes:
1. Live Mode (default): Queries the official abuse.ch URLhaus API v1 endpoint.
   Requires URLHAUS_AUTH_KEY in the environment or in backend/.env.
2. Simulated/Demo Mode (--demo or --mock): Runs an end-to-end smoke test using
   a realistic URLhaus response without requiring an active Auth-Key or internet access.

USAGE:
    python backend/scripts/smoke_test_urlhaus.py [URL]
    python backend/scripts/smoke_test_urlhaus.py --demo [URL]

EXAMPLES:
    python backend/scripts/smoke_test_urlhaus.py --demo
    python backend/scripts/smoke_test_urlhaus.py https://example.com/
"""

import json
import os
import sys
from pathlib import Path
import urllib.parse
import httpx

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add backend directory to sys.path so app packages can be imported
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.services.urlhaus_client import (
    URLhausClient,
    URLhausConfigError,
    URLhausError,
    urlhaus_client,
)


def run_demo_smoke_test(url: str = "https://example.com/sample_download.bin"):
    print("=" * 70)
    print("CyberOrchestra URLhaus Smoke Test (Demo / Simulated Mode)")
    print("=" * 70)
    print(f"[*] Target URL:         {url}")
    print("[*] Mode:               Mock Transport (Simulated URLhaus API v1)")

    sample_api_response = {
        "query_status": "ok",
        "id": "1847120",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/1847120/",
        "url": url,
        "url_status": "offline",
        "host": urllib.parse.urlparse(url).netloc,
        "date_added": "2026-09-30 06:45:10 UTC",
        "threat": "malware_download",
        "reporter": "community_researcher",
        "larted": "true",
        "tags": ["payload", "test_stub", "bin"],
        "blacklists": {
            "spamhaus_dbl": "not listed",
            "surbl": "not listed",
        },
        "payloads": [
            {
                "response_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "file_type": "bin",
                "signature": "SimulatedTrojan.VariantA",
            }
        ],
    }

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=sample_api_response)

    client = Abuse_or_URLhaus_client = URLhausClient(auth_key="demo_simulated_key")
    result = client.check_and_convert(url=url, transport=httpx.MockTransport(mock_handler))

    print("\n[+] SUCCESS! Smoke test completed. Normalized evidence generated:\n")
    print("--- 1. Extracted URLhaus Reputation ---")
    print(result.reputation.model_dump_json(indent=2))

    print("\n--- 2. Standardized CyberOrchestra Indicator ---")
    print(result.indicator.model_dump_json(indent=2))

    print("\n--- 3. Standardized CyberOrchestra Evidence ---")
    print(result.evidence.model_dump_json(indent=2))

    print("\n" + "=" * 70)
    print("Smoke Test Passed: URLhaus normalizer schema contracts fully satisfied.")
    print("=" * 70)


def run_live_smoke_test(url: str):
    print("=" * 70)
    print("CyberOrchestra URLhaus Live Smoke Test")
    print("=" * 70)

    # 1. Check Auth Key configuration
    auth_key = settings.URLHAUS_AUTH_KEY or os.getenv("URLHAUS_AUTH_KEY")
    if not auth_key or not auth_key.strip():
        print("\n[!] URLHAUS_AUTH_KEY is not configured in environment or backend/.env.")
        print("    Running in --demo mode to verify pipeline correctness:\n")
        run_demo_smoke_test(url)
        print("\n[INFO] To run with live API against https://urlhaus-api.abuse.ch:")
        print("  1. Add your key to backend/.env:  URLHAUS_AUTH_KEY=your_key_here")
        print(f"  2. Re-run: python backend/scripts/smoke_test_urlhaus.py \"{url}\"")
        return

    print("\n[*] Auth-Key Status:   [CONFIGURED / PROTECTED]")
    print(f"[*] Target Endpoint:     {settings.URLHAUS_API_URL}")
    print(f"[*] Target URL:          {url}")

    # 2. Syntax check
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        print(f"\n[ERROR] Invalid URL syntax: '{url}'. Must start with http:// or https://")
        sys.exit(1)

    # 3. Perform live query and conversion
    print("\n[*] Sending request to URLhaus API v1 query endpoint...")
    try:
        result = urlhaus_client.check_and_convert(url=url)
    except URLhausConfigError as e:
        print(f"\n[ERROR] Configuration error: {e}")
        sys.exit(1)
    except URLhausError as e:
        print(f"\n[ERROR] URLhaus API communication failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)

    # 4. Display results
    print("\n[+] SUCCESS! Live URLhaus intelligence retrieved and converted into standardized schema:\n")
    print("--- Extracted URLhaus Reputation ---")
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

    target_url = args[0].strip() if args else "https://example.com/test_resource"

    if is_demo:
        run_demo_smoke_test(target_url)
    else:
        run_live_smoke_test(target_url)
