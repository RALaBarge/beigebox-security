"""Tests for MCP Parameter Validation router and integration layer."""

import pytest
from fastapi.testclient import TestClient


PREFIX = "/v1/security/parameters"


# ---------------------------------------------------------------------------
# Valid parameters for all 9 tools
# ---------------------------------------------------------------------------


class TestValidParameters:
    """All 9 tools should pass with legitimate parameters."""

    def test_workspace_file_read(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "out/report.md"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["issues"] == []

    def test_workspace_file_write(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "write", "path": "out/new.txt", "content": "hello"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_workspace_file_list(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "list"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_network_audit_valid_subnet(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "network_audit",
            "parameters": {"network": "192.168.1.0/24", "ports": "22,80,443"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_network_audit_valid_ip(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "network_audit",
            "parameters": {"ip": "10.0.0.1"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_cdp_valid_url(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "cdp",
            "parameters": {"url": "https://example.com/page", "selector": "#main"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_python_interpreter_safe_code(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "python_interpreter",
            "parameters": {"code": "import math\nresult = math.sqrt(16)\nprint(result)"},
        })
        assert resp.status_code == 200
        # python_interpreter expects code as a string, but dict with "code" key
        # should be parsed. The validator receives dict params.
        data = resp.json()
        # The dict itself isn't a string, so it goes through _parse_params as dict
        # and then _validate_python gets parsed=dict, raw=dict
        # The code key inside should be fine since it only has safe imports
        assert data["valid"] is True

    def test_apex_analyzer_valid_soql(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "apex_analyzer",
            "parameters": {"soql_query": "SELECT Id, Name FROM Account WHERE Name = 'Acme'"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_confluence_crawler_valid(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "confluence_crawler",
            "parameters": {"url": "https://wiki.example.com/display/TEAM/Page"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_web_scraper_valid(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "web_scraper",
            "parameters": {"url": "https://example.com/article"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_browserbox_valid_navigate(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "browserbox",
            "parameters": {"tool": "navigate", "input": "https://example.com"},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_bluetruth_valid(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "bluetruth",
            "parameters": {"command": "scan", "timeout": 10},
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True


# ---------------------------------------------------------------------------
# Invalid parameters: attack detection
# ---------------------------------------------------------------------------


class TestPathTraversal:

    def test_dot_dot_slash(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "../../etc/passwd"},
        })
        data = resp.json()
        assert data["valid"] is False
        assert any(i["attack_type"] == "path_traversal" for i in data["issues"])

    def test_url_encoded_traversal(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "%2e%2e%2fetc/shadow"},
        })
        data = resp.json()
        assert data["valid"] is False

    def test_null_byte(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "out/file.txt\x00.jpg"},
        })
        data = resp.json()
        assert data["valid"] is False
        assert any(i["attack_type"] == "path_traversal" for i in data["issues"])

    def test_absolute_path_outside_workspace(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "/etc/passwd"},
        })
        data = resp.json()
        assert data["valid"] is False


class TestSSRF:

    def test_localhost_cdp(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "cdp",
            "parameters": {"url": "http://localhost:9222/json"},
        })
        data = resp.json()
        assert data["valid"] is False
        assert any(i["attack_type"] == "ssrf" for i in data["issues"])

    def test_internal_ip_web_scraper(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "web_scraper",
            "parameters": {"url": "http://169.254.169.254/latest/meta-data/"},
        })
        data = resp.json()
        assert data["valid"] is False

    def test_public_ip_network_audit(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "network_audit",
            "parameters": {"network": "8.8.8.0/24"},
        })
        data = resp.json()
        assert data["valid"] is False
        assert any(i["attack_type"] == "ssrf" for i in data["issues"])

    def test_dangerous_scheme_confluence(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "confluence_crawler",
            "parameters": {"url": "file:///etc/passwd"},
        })
        data = resp.json()
        assert data["valid"] is False


class TestCodeInjection:

    def test_dangerous_import(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "python_interpreter",
            "parameters": {"code": "import os\nos.system('rm -rf /')"},
        })
        data = resp.json()
        assert data["valid"] is False
        assert any(i["attack_type"] == "code_injection" for i in data["issues"])

    def test_dunder_escape(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "python_interpreter",
            "parameters": {"code": "''.__class__.__mro__[1].__subclasses__()"},
        })
        data = resp.json()
        assert data["valid"] is False

    def test_eval_exec(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "python_interpreter",
            "parameters": {"code": "eval('__import__(\"os\").system(\"id\")')"},
        })
        data = resp.json()
        assert data["valid"] is False

    def test_shell_injection_bluetruth(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "bluetruth",
            "parameters": {"command": "scan; rm -rf /"},
        })
        data = resp.json()
        assert data["valid"] is False
        assert any(i["attack_type"] == "code_injection" for i in data["issues"])


class TestReDoS:

    def test_nested_quantifier(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "apex_analyzer",
            "parameters": {"query": "(a+)+b"},
        })
        data = resp.json()
        assert data["valid"] is False
        assert any(i["attack_type"] == "redos" for i in data["issues"])

    def test_sql_injection_in_soql(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "apex_analyzer",
            "parameters": {"soql_query": "SELECT Id FROM Account WHERE Name = '' OR '1'='1'"},
        })
        data = resp.json()
        assert data["valid"] is False
        assert any(i["attack_type"] == "sql_injection" for i in data["issues"])


# ---------------------------------------------------------------------------
# False positives: legitimate params that look suspicious
# ---------------------------------------------------------------------------


class TestFalsePositives:

    def test_legitimate_path_with_dots(self, client: TestClient):
        """A filename like 'v2.0.report.md' should not trigger path traversal."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "out/v2.0.report.md"},
        })
        assert resp.json()["valid"] is True

    def test_legitimate_soql_with_quotes(self, client: TestClient):
        """SOQL with quoted string values should not trigger SQL injection."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "apex_analyzer",
            "parameters": {"soql_query": "SELECT Id FROM Contact WHERE Name = 'O\\'Brien'"},
        })
        assert resp.json()["valid"] is True

    def test_safe_python_imports(self, client: TestClient):
        """Importing math, json, re etc should be fine."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "python_interpreter",
            "parameters": {"code": "import json\nimport math\nimport re\nprint(json.dumps({'pi': math.pi}))"},
        })
        assert resp.json()["valid"] is True

    def test_public_url_is_fine(self, client: TestClient):
        """Normal public URLs should pass CDP validation."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "cdp",
            "parameters": {"url": "https://docs.python.org/3/library/re.html"},
        })
        assert resp.json()["valid"] is True

    def test_network_audit_common_ports_keyword(self, client: TestClient):
        """Using 'common' or 'top1000' as port spec should be valid."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "network_audit",
            "parameters": {"network": "192.168.1.0/24", "ports": "common"},
        })
        assert resp.json()["valid"] is True


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------


class TestSeverityLevels:

    def test_critical_severity(self, client: TestClient):
        """Path traversal should be critical."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "../../../etc/shadow"},
        })
        issues = resp.json()["issues"]
        assert any(i["severity"] == "critical" for i in issues)

    def test_medium_severity(self, client: TestClient):
        """Port count exceeding limit should be medium."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "network_audit",
            "parameters": {"network": "192.168.1.0/24", "ports": "1-200"},
        })
        issues = resp.json()["issues"]
        assert any(i["severity"] == "medium" for i in issues)

    def test_high_severity(self, client: TestClient):
        """Public IP in network audit should be critical (ssrf)."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "network_audit",
            "parameters": {"ip": "8.8.8.8"},
        })
        issues = resp.json()["issues"]
        assert any(i["severity"] == "critical" for i in issues)


# ---------------------------------------------------------------------------
# Batch validation
# ---------------------------------------------------------------------------


class TestBatchValidation:

    def test_batch_mixed(self, client: TestClient):
        """Batch with mix of valid and invalid should return per-item results."""
        resp = client.post(f"{PREFIX}/validate-batch", json={
            "requests": [
                {"tool_name": "workspace_file", "parameters": {"action": "read", "path": "out/ok.md"}},
                {"tool_name": "workspace_file", "parameters": {"action": "read", "path": "../../etc/passwd"}},
                {"tool_name": "web_scraper", "parameters": {"url": "https://example.com"}},
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert data["valid_count"] == 2
        assert data["invalid_count"] == 1
        assert data["results"][0]["valid"] is True
        assert data["results"][1]["valid"] is False
        assert data["results"][2]["valid"] is True

    def test_batch_empty(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate-batch", json={"requests": []})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["valid_count"] == 0


# ---------------------------------------------------------------------------
# Rule retrieval
# ---------------------------------------------------------------------------


class TestRuleRetrieval:

    def test_get_workspace_file_rules(self, client: TestClient):
        resp = client.get(f"{PREFIX}/rules/workspace_file")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tool"] == "workspace_file"
        assert "path_traversal" in data["attack_vectors"]
        assert "action" in data["parameters"]

    def test_get_python_rules(self, client: TestClient):
        resp = client.get(f"{PREFIX}/rules/python_interpreter")
        assert resp.status_code == 200
        data = resp.json()
        assert "code_injection" in data["attack_vectors"]

    def test_get_unknown_tool_404(self, client: TestClient):
        resp = client.get(f"{PREFIX}/rules/nonexistent_tool")
        assert resp.status_code == 404

    def test_python_alias(self, client: TestClient):
        """'python' should resolve to python_interpreter rules."""
        resp = client.get(f"{PREFIX}/rules/python")
        assert resp.status_code == 200
        assert resp.json()["tool"] == "python_interpreter"


# ---------------------------------------------------------------------------
# Remediation hints
# ---------------------------------------------------------------------------


class TestRemediation:

    def test_remediation_present(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "../escape"},
        })
        issues = resp.json()["issues"]
        assert len(issues) > 0
        assert issues[0]["remediation"] != ""
        assert "relative path" in issues[0]["remediation"].lower() or "remove" in issues[0]["remediation"].lower()


# ---------------------------------------------------------------------------
# allow_unsafe flag
# ---------------------------------------------------------------------------


class TestAllowUnsafe:

    def test_allow_unsafe_downgrades_non_critical(self, client: TestClient):
        """With allow_unsafe=True, medium/high issues should still pass."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "network_audit",
            "parameters": {"network": "192.168.1.0/24", "ports": "1-200"},
            "allow_unsafe": True,
        })
        data = resp.json()
        # Port count medium issue should be downgraded
        assert data["valid"] is True
        assert len(data["issues"]) > 0  # Issues still reported

    def test_allow_unsafe_still_blocks_critical(self, client: TestClient):
        """Critical issues should still fail even with allow_unsafe."""
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "../../../etc/passwd"},
            "allow_unsafe": True,
        })
        data = resp.json()
        assert data["valid"] is False


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------


class TestResponseShape:

    def test_elapsed_ms_present(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "list"},
        })
        data = resp.json()
        assert "elapsed_ms" in data
        assert isinstance(data["elapsed_ms"], float)
        assert data["elapsed_ms"] >= 0

    def test_sanitized_parameters_present(self, client: TestClient):
        resp = client.post(f"{PREFIX}/validate", json={
            "tool_name": "workspace_file",
            "parameters": {"action": "read", "path": "out/test.md"},
        })
        data = resp.json()
        assert "sanitized_parameters" in data
        assert "path" in data["sanitized_parameters"]
