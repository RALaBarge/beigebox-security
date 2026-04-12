"""Pytest configuration and fixtures."""

import pytest
from fastapi.testclient import TestClient

from beigebox_security.api import create_app


@pytest.fixture
def app():
    """Create app instance for testing."""
    return create_app()


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def async_client(app):
    """Create async test client."""
    from httpx import AsyncClient

    return AsyncClient(app=app, base_url="http://test")
