"""Integration tests for all CyberOrchestra API endpoints."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint():
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "CyberOrchestra is running" in data["message"]


def test_system_health_endpoint():
    res = client.get("/api/v1/system/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert len(data["components"]) == 8
    names = [c["component"] for c in data["components"]]
    assert "FastAPI Backend" in names
    assert "Deterministic Policy Engine" in names
    assert "Shared Incident State" in names
    assert "AbuseIPDB Threat Feed" in names
    assert "URLhaus Intelligence" in names
    assert "NVD CVE API 2.0" in names
    assert "MITRE ATT&CK Client" in names
    assert "LLM Service (Groq)" in names


def test_system_agents_endpoint():
    res = client.get("/api/v1/system/agents")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 8
    agent_ids = [a["id"] for a in data]
    assert "data-normalizer" in agent_ids
    assert "threat-detection" in agent_ids
    assert "malware-analysis" in agent_ids
    assert "log-analysis" in agent_ids
    assert "vuln-assessment" in agent_ids
    assert "recovery-planning" in agent_ids
    assert "policy-engine" in agent_ids
    assert "report-generation" in agent_ids


def test_dashboard_stats_endpoint():
    res = client.get("/api/v1/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "kpis" in data
    assert "severityDistribution" in data
    assert "pipelineThroughput" in data
    assert "incidentTrend" in data
    assert "recentIncidents" in data
    assert "recentActivity" in data
    assert data["kpis"]["totalIncidents"] >= 5


def test_incidents_list_and_scenarios():
    res = client.get("/api/v1/incidents")
    assert res.status_code == 200
    incidents = res.json()
    assert len(incidents) >= 5

    scenarios_res = client.get("/api/v1/incidents/scenarios")
    assert scenarios_res.status_code == 200
    scenarios = scenarios_res.json()
    assert len(scenarios) == 5
    filenames = [s["filename"] for s in scenarios]
    assert "incident_001_network.json" in filenames


def test_incident_detail_and_not_found():
    res = client.get("/api/v1/incidents")
    inc_id = res.json()[0]["id"]

    detail_res = client.get(f"/api/v1/incidents/{inc_id}")
    assert detail_res.status_code == 200
    data = detail_res.json()
    assert data["incident"]["incident_id"] == inc_id
    assert "indicators" in data["incident"]
    assert "evidence" in data["incident"]

    nf_res = client.get("/api/v1/incidents/NON_EXISTENT_999")
    assert nf_res.status_code == 404


def test_create_incident_valid_and_invalid():
    valid_payload = {
        "incident_id": "INC-TEST-CUSTOM-01",
        "incident_type": "suspicious_network_activity",
        "description": "Custom API test incident telemetry",
        "source": "api_test",
        "indicators": [
            {"type": "ip", "value": "203.0.113.88", "source": "test"},
        ],
        "evidence": [
            {
                "evidence_id": "EVID-TEST-001",
                "evidence_type": "network_log",
                "source": "test",
                "description": "Network test observation",
            }
        ],
    }
    create_res = client.post("/api/v1/incidents", json=valid_payload)
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["id"] == "INC-TEST-CUSTOM-01"

    # Malformed payload
    invalid_res = client.post("/api/v1/incidents", json={"invalid_key": 123})
    assert invalid_res.status_code == 400


def test_run_pipeline_end_to_end():
    # Load or pick an incident
    res = client.get("/api/v1/incidents")
    inc_id = res.json()[0]["id"]

    # Run the full pipeline
    pipeline_res = client.post(f"/api/v1/incidents/{inc_id}/run-pipeline")
    assert pipeline_res.status_code == 200
    result = pipeline_res.json()
    assert result["incident_id"] == inc_id
    assert len(result["stages"]) >= 7
    assert result["report_generated"] is True

    # Verify policy reviews were created
    reviews_res = client.get("/api/v1/policy/reviews")
    assert reviews_res.status_code == 200
    reviews = reviews_res.json()
    assert len(reviews) > 0

    # Verify report was created
    reports_res = client.get("/api/v1/reports")
    assert reports_res.status_code == 200
    reports = reports_res.json()
    assert len(reports) > 0


def test_policy_approval_workflow():
    reviews_res = client.get("/api/v1/policy/reviews")
    reviews = reviews_res.json()
    assert len(reviews) > 0
    first_rev = reviews[0]

    # Test approve
    approve_res = client.post(f"/api/v1/policy/reviews/{first_rev['id']}/approve", json={"notes": "Approved by SOC Lead"})
    assert approve_res.status_code == 200
    assert approve_res.json()["human_status"] == "Approved"

    # Test reject on non-existent
    bad_res = client.post("/api/v1/policy/reviews/POL-NON-EXISTENT/reject")
    assert bad_res.status_code == 404


def test_intelligence_feed_and_sources():
    feed_res = client.get("/api/v1/intelligence/feed")
    assert feed_res.status_code == 200
    feed = feed_res.json()
    assert isinstance(feed, list)
    assert len(feed) > 0

    sources_res = client.get("/api/v1/intelligence/sources")
    assert sources_res.status_code == 200
    sources = sources_res.json()
    assert len(sources) == 4
    names = [s["name"] for s in sources]
    assert "AbuseIPDB" in names
    assert "URLhaus" in names
    assert "NVD CVE API 2.0" in names
    assert "MITRE ATT&CK" in names


def test_evaluation_endpoints():
    get_res = client.get("/api/v1/evaluation/results")
    assert get_res.status_code == 200
    data = get_res.json()
    assert "benchmark_dataset" in data

    run_res = client.post("/api/v1/evaluation/run")
    assert run_res.status_code == 200
    eval_data = run_res.json()
    assert eval_data["tested"] is True
    assert "multi_agent" in eval_data
    assert "single_llm_baseline" in eval_data
    assert "metrics" in eval_data["multi_agent"]
    assert "policy_compliance_rate" in eval_data["multi_agent"]["metrics"]
