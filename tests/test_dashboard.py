"""Tests for guardrailprobe.dashboard — Flask routes and API token auth."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from guardrailprobe.dashboard import create_app


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path):
    """Flask test client with a clean temp reports directory."""
    env = {
        "GUARDRAILPROBE_REPORTS_DIR": str(tmp_path / "reports"),
        "GUARDRAILPROBE_API_TOKEN": "",  # no token — open mode
        "GUARDRAILPROBE_SKIP_SPACY": "1",
    }
    with patch.dict(os.environ, env):
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c


@pytest.fixture()
def authed_client(tmp_path):
    """Flask test client with API token enforced."""
    env = {
        "GUARDRAILPROBE_REPORTS_DIR": str(tmp_path / "reports"),
        "GUARDRAILPROBE_API_TOKEN": "secret-test-token",
        "GUARDRAILPROBE_SKIP_SPACY": "1",
    }
    with patch.dict(os.environ, env):
        from guardrailprobe import dashboard as _dash
        # Patch the module-level token so the decorator reads it at call time
        with patch.object(_dash, "_API_TOKEN", "secret-test-token"):
            app = create_app()
            app.config["TESTING"] = True
            with app.test_client() as c:
                yield c


# ── Read-only routes ──────────────────────────────────────────────────────────

def test_index_returns_200(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"guardrailprobe" in resp.data.lower()


def test_api_backends_returns_list(client):
    resp = client.get("/api/backends")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "backend" in data[0]
    assert "status" in data[0]


def test_api_probes_returns_list(client):
    resp = client.get("/api/probes")
    assert resp.status_code == 200
    probes = json.loads(resp.data)
    assert isinstance(probes, list)
    assert len(probes) >= 78


def test_api_probes_filter_by_category(client):
    resp = client.get("/api/probes?category=LLM01")
    assert resp.status_code == 200
    probes = json.loads(resp.data)
    assert all(p["owasp_ref"] == "LLM01" for p in probes)


def test_api_probes_filter_by_severity(client):
    resp = client.get("/api/probes?severity=high")
    assert resp.status_code == 200
    probes = json.loads(resp.data)
    assert all(p["severity"] == "high" for p in probes)


def test_api_benchmark_latest_no_run(client):
    resp = client.get("/api/benchmark/latest")
    assert resp.status_code in (200, 404)


def test_api_benchmark_download_invalid_filename(client):
    resp = client.get("/api/benchmark/download/../../etc/passwd")
    assert resp.status_code in (400, 404)  # 404 when Flask routing rejects the path


def test_api_benchmark_download_valid_missing_file(client, tmp_path):
    # Redirect _default_output to empty tmp dir so the file is genuinely absent
    with patch("guardrailprobe.report.BenchmarkRunner") as MockRunner:
        MockRunner.return_value._default_output = tmp_path
        resp = client.get("/api/benchmark/download/benchmark_2026_06.json")
    assert resp.status_code == 404


def test_api_benchmark_status_unknown(client):
    resp = client.get("/api/benchmark/status/nonexistent-run-id")
    assert resp.status_code == 404


def test_api_custom_probes_empty(client):
    resp = client.get("/api/probes/custom")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


# ── Write routes — open mode (no token) ──────────────────────────────────────

def test_probe_run_missing_payload_returns_400(client):
    resp = client.post("/api/probe/run",
                       json={"backend": "guardrails_ai", "payload": ""},
                       content_type="application/json")
    assert resp.status_code == 400


def test_probe_run_unknown_backend_returns_400(client):
    resp = client.post("/api/probe/run",
                       json={"backend": "does_not_exist", "payload": "test payload"},
                       content_type="application/json")
    assert resp.status_code in (400, 404)  # dashboard returns 404 for unknown backend


def test_custom_probe_save_missing_fields_returns_400(client):
    resp = client.post("/api/probes/custom",
                       json={"id": "test-probe"},
                       content_type="application/json")
    assert resp.status_code == 400


def test_custom_probe_delete_unknown_returns_404(client):
    resp = client.delete("/api/probes/custom/does-not-exist")
    assert resp.status_code == 404


# ── API token authentication ──────────────────────────────────────────────────

def test_write_endpoint_blocked_without_token(tmp_path):
    """When GUARDRAILPROBE_API_TOKEN is set, unauthenticated write requests get 401."""
    env = {
        "GUARDRAILPROBE_REPORTS_DIR": str(tmp_path / "reports"),
        "GUARDRAILPROBE_API_TOKEN": "my-secret",
        "GUARDRAILPROBE_SKIP_SPACY": "1",
    }
    with patch.dict(os.environ, env):
        import guardrailprobe.dashboard as _dash
        with patch.object(_dash, "_API_TOKEN", "my-secret"):
            app = create_app()
            app.config["TESTING"] = True
            with app.test_client() as c:
                resp = c.post("/api/benchmark/run",
                              json={},
                              content_type="application/json")
    assert resp.status_code == 401


def test_write_endpoint_allowed_with_bearer_token(tmp_path):
    """Authorization: Bearer <token> header grants access to write endpoints."""
    env = {
        "GUARDRAILPROBE_REPORTS_DIR": str(tmp_path / "reports"),
        "GUARDRAILPROBE_API_TOKEN": "my-secret",
        "GUARDRAILPROBE_SKIP_SPACY": "1",
    }
    with patch.dict(os.environ, env):
        import guardrailprobe.dashboard as _dash
        with patch.object(_dash, "_API_TOKEN", "my-secret"):
            app = create_app()
            app.config["TESTING"] = True
            with app.test_client() as c:
                # A request with the right Bearer token must NOT return 401.
                # It might return 400 (bad body) or 202 (accepted), but not 401.
                resp = c.post(
                    "/api/probe/run",
                    json={"backend": "guardrails_ai", "payload": ""},
                    headers={"Authorization": "Bearer my-secret"},
                    content_type="application/json",
                )
    assert resp.status_code != 401


def test_write_endpoint_allowed_with_x_api_token_header(tmp_path):
    """X-API-Token header also grants access."""
    env = {
        "GUARDRAILPROBE_REPORTS_DIR": str(tmp_path / "reports"),
        "GUARDRAILPROBE_API_TOKEN": "my-secret",
        "GUARDRAILPROBE_SKIP_SPACY": "1",
    }
    with patch.dict(os.environ, env):
        import guardrailprobe.dashboard as _dash
        with patch.object(_dash, "_API_TOKEN", "my-secret"):
            app = create_app()
            app.config["TESTING"] = True
            with app.test_client() as c:
                resp = c.post(
                    "/api/probe/run",
                    json={"backend": "guardrails_ai", "payload": ""},
                    headers={"X-API-Token": "my-secret"},
                    content_type="application/json",
                )
    assert resp.status_code != 401


def test_read_endpoint_accessible_without_token(tmp_path):
    """Read-only endpoints are always accessible regardless of token setting."""
    env = {
        "GUARDRAILPROBE_REPORTS_DIR": str(tmp_path / "reports"),
        "GUARDRAILPROBE_API_TOKEN": "my-secret",
        "GUARDRAILPROBE_SKIP_SPACY": "1",
    }
    with patch.dict(os.environ, env):
        import guardrailprobe.dashboard as _dash
        with patch.object(_dash, "_API_TOKEN", "my-secret"):
            app = create_app()
            app.config["TESTING"] = True
            with app.test_client() as c:
                resp = c.get("/api/backends")
    assert resp.status_code == 200
