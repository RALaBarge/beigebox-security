"""Tests for health check endpoints."""

import pytest


@pytest.mark.unit
def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"


@pytest.mark.unit
def test_ping(client):
    """Test ping endpoint."""
    response = client.get("/ping")
    assert response.status_code == 200
    data = response.json()
    assert data["pong"] is True
