"""Tests for POST /api/v1/normalize API endpoint."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_api_normalize_valid_payload():
    """Test successful normalization via API endpoint."""
    payload = {
        "incident_id": "INC-API-001",
        "incident_type": "suspicious_network_activity",
        "description": "Multiple connections to a suspicious external IP",
        "indicators": [
            {
                "type": "ip",
                "value": "203.0.113.10",
                "source": "simulated",
            }
        ],
    }

    response = client.post("/api/v1/normalize", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["incident_id"] == "INC-API-001"
    assert data["incident_type"] == "suspicious_network_activity"
    assert data["description"] == "Multiple connections to a suspicious external IP"
    assert data["indicators"][0]["indicator_type"] == "ip"
    assert data["indicators"][0]["value"] == "203.0.113.10"
    assert data["indicators"][0]["source"] == "simulated"
    assert "timestamp" in data


def test_api_normalize_missing_incident_id():
    """Test that omitting incident_id results in a 400 Bad Request error."""
    payload = {
        "incident_type": "suspicious_network_activity",
        "description": "Missing id payload",
    }

    response = client.post("/api/v1/normalize", json=payload)
    assert response.status_code == 400
    assert "Missing required field: 'incident_id'" in response.json()["detail"]


def test_api_normalize_missing_description():
    """Test that omitting description results in a 400 Bad Request error."""
    payload = {
        "incident_id": "INC-API-002",
        "incident_type": "suspicious_network_activity",
    }

    response = client.post("/api/v1/normalize", json=payload)
    assert response.status_code == 400
    assert "Missing required field: 'description'" in response.json()["detail"]


def test_api_normalize_malformed_indicator():
    """Test that an indicator without value results in a 400 Bad Request error."""
    payload = {
        "incident_id": "INC-API-003",
        "incident_type": "phishing",
        "description": "Phishing email link",
        "indicators": [
            {
                "type": "url"
                # Missing value
            }
        ],
    }

    response = client.post("/api/v1/normalize", json=payload)
    assert response.status_code == 400
    assert "missing a required 'value'" in response.json()["detail"]
