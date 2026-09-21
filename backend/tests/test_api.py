def test_health(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert "status" in body


def test_config(client):
    resp = client.get("/api/v1/config")
    assert resp.status_code == 200
    assert "safe_threshold" in resp.json()


def test_demo_url_analysis(client):
    resp = client.post("/api/v1/analyze/url", json={"url": "http://example.com", "demo": True})
    assert resp.status_code == 200
    body = resp.json()
    assert body["demo"] is True
    assert "risk_level" in body


def test_history_and_alerts_shape(client):
    resp = client.get("/api/v1/history?limit=5")
    assert resp.status_code == 200
    assert "items" in resp.json()

    resp = client.get("/api/v1/alerts?limit=5")
    assert resp.status_code == 200
    assert "items" in resp.json()


def test_feedback_endpoint(client):
    resp = client.post("/api/v1/feedback", json={"analysis_id": "does-not-exist", "correct": True})
    assert resp.status_code == 200


def test_ssrf_rejected_for_non_demo_url(client):
    resp = client.post("/api/v1/analyze/url", json={"url": "http://127.0.0.1/admin", "demo": False})
    assert resp.status_code == 400
