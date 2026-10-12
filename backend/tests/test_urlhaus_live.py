"""Live integration smoke test for URLhaus API.

This test is automatically skipped in standard pytest runs unless
the URLHAUS_AUTH_KEY environment variable is explicitly provided.
"""

import os
import pytest

from app.models.urlhaus import URLReputationResult
from app.services.urlhaus_client import URLhausClient

URLHAUS_KEY = os.getenv("URLHAUS_AUTH_KEY")
TARGET_LIVE_URL = os.getenv("URLHAUS_TEST_URL", "https://example.com/")


@pytest.mark.skipif(
    not URLHAUS_KEY,
    reason="URLHAUS_AUTH_KEY environment variable is not set; skipping live external test.",
)
def test_live_urlhaus_reputation_lookup():
    """Execute live query against URLhaus when key is explicitly configured."""
    client = URLhausClient(auth_key=URLHAUS_KEY)
    result = client.check_and_convert(TARGET_LIVE_URL)

    assert isinstance(result, URLReputationResult)
    assert result.url == TARGET_LIVE_URL
    assert result.indicator.source == "URLhaus"
    assert result.indicator.confidence is None
    assert result.evidence.evidence_type == "url_reputation"
    assert result.evidence.confidence is None
    assert result.reputation.query_status is not None
