"""Live integration smoke test for AbuseIPDB API.

This test is automatically skipped in standard pytest runs unless
the ABUSEIPDB_API_KEY environment variable is explicitly provided.
"""

import os
import pytest

from app.models.abuseipdb import IPReputationResult
from app.services.abuseipdb_client import AbuseIPDBClient

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
TARGET_LIVE_IP = os.getenv("ABUSEIPDB_TEST_IP", "1.1.1.1")


@pytest.mark.skipif(
    not ABUSEIPDB_KEY,
    reason="ABUSEIPDB_API_KEY environment variable is not set; skipping live external test.",
)
def test_live_abuseipdb_reputation_lookup():
    """Execute live query against AbuseIPDB when key is explicitly set."""
    client = AbuseIPDBClient(api_key=ABUSEIPDB_KEY)
    result = client.check_and_convert(TARGET_LIVE_IP)

    assert isinstance(result, IPReputationResult)
    assert result.ip_address == TARGET_LIVE_IP
    assert result.indicator.source == "AbuseIPDB"
    assert result.indicator.confidence is None
    assert result.evidence.evidence_type == "network_reputation"
    assert result.evidence.confidence is None
    assert result.reputation.abuse_confidence_score is not None
