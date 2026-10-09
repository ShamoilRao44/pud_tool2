from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import create_app


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "mini_system"


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_health_and_run(client):
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    body = health.get_json()
    assert body["ok"] is True
    assert 1 in body["implemented_stages"]

    response = client.post(
        "/api/v1/runs",
        json={"stages": [1], "source_dir": str(FIXTURE_DIR), "options": {"determinism_check": True}},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["stage1_running_confirmed"] is True
    assert payload["verification"]["verified"] is True
    assert payload["stages"][0]["stage"] == 1


def test_stage2_not_implemented(client):
    response = client.post("/api/v1/stages/2/run", json={"source_dir": str(FIXTURE_DIR)})
    assert response.status_code == 501
    body = response.get_json()
    assert body["error"]["code"] == "STAGE_NOT_IMPLEMENTED"


def test_unknown_run_returns_404(client):
    response = client.get("/api/v1/runs/nope")
    assert response.status_code == 404
    body = response.get_json()
    assert body["error"]["code"] == "RUN_NOT_FOUND"


def test_artifact_path_traversal_rejected(client):
    run_response = client.post("/api/v1/runs", json={"stages": [1], "source_dir": str(FIXTURE_DIR)})
    run_id = run_response.get_json()["run_id"]
    response = client.get(f"/api/v1/runs/{run_id}/stages/1/artifacts/../../../../etc/passwd")
    assert response.status_code == 400
    body = response.get_json()
    assert body["error"]["code"] == "INVALID_ARTIFACT_NAME"
